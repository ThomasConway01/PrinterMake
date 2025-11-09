#!/usr/bin/env python3
"""
PrinterMake - Standalone CLI Chat Interface
A continuous-running chat client like Gemini CLI with server management
"""

import asyncio
import websockets
import json
import os
import sys
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional
import argparse
import getpass
import base64
import configparser
import re

# Add the server directory to path to import encryption module
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'Server'))

try:
    from encryption import EncryptionManager, generate_new_encryption_manager
except ImportError:
    print("Error: Could not import encryption module. Make sure encryption.py is in the Server directory.")
    sys.exit(1)

class ServerConfig:
    """Manage multiple server configurations"""
    
    def __init__(self, config_file="server_config.ini"):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load_config()
    
    def load_config(self):
        """Load server configuration from file"""
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
    
    def save_config(self):
        """Save server configuration to file"""
        with open(self.config_file, 'w') as f:
            self.config.write(f)
    
    def add_server(self, name, host, port=8765):
        """Add a new server configuration"""
        if not self.config.has_section('servers'):
            self.config.add_section('servers')
        
        self.config.set('servers', name, f"{host}:{port}")
        self.save_config()
        return True
    
    def get_server(self, name):
        """Get server configuration by name"""
        if not self.config.has_section('servers'):
            return None
        
        server_str = self.config.get('servers', name, fallback=None)
        if server_str and ':' in server_str:
            host, port = server_str.rsplit(':', 1)
            return {"host": host, "port": int(port)}
        return None
    
    def list_servers(self):
        """List all configured servers"""
        if not self.config.has_section('servers'):
            return {}
        
        servers = {}
        for name in self.config.options('servers'):
            server_str = self.config.get('servers', name)
            if ':' in server_str:
                host, port = server_str.rsplit(':', 1)
                servers[name] = {"host": host, "port": int(port)}
        return servers
    
    def get_default_server(self):
        """Get the default server (printermake)"""
        default = self.get_server("printermake")
        if default:
            return default
        
        # Create default printermake.com server
        self.add_server("printermake", "printermake.com", 8765)
        return {"host": "printermake.com", "port": 8765}

class UserConfig:
    """Manage user login and settings"""
    
    def __init__(self, config_file="user_config.ini"):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load_config()
        self.username = None
        self.ui_mode = "normal"  # normal or cyberpunk
    
    def load_config(self):
        """Load user configuration from file"""
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
    
    def save_config(self):
        """Save user configuration to file"""
        with open(self.config_file, 'w') as f:
            self.config.write(f)
    
    def is_logged_in(self):
        """Check if user is logged in"""
        return self.config.has_section('user') and self.config.has_option('user', 'username')
    
    def login(self, username):
        """Login user"""
        if not self.config.has_section('user'):
            self.config.add_section('user')
        
        self.config.set('user', 'username', username)
        self.username = username
        self.save_config()
        return True
    
    def logout(self):
        """Logout user"""
        if self.config.has_section('user'):
            self.config.remove_section('user')
        self.username = None
        self.save_config()
    
    def get_username(self):
        """Get current username"""
        if not self.username and self.config.has_section('user'):
            self.username = self.config.get('user', 'username', fallback=None)
        return self.username
    
    def set_ui_mode(self, mode):
        """Set UI mode (normal or cyberpunk)"""
        if not self.config.has_section('settings'):
            self.config.add_section('settings')
        
        self.config.set('settings', 'ui_mode', mode)
        self.ui_mode = mode
        self.save_config()
    
    def get_ui_mode(self):
        """Get UI mode"""
        if not self.ui_mode:
            if self.config.has_section('settings'):
                self.ui_mode = self.config.get('settings', 'ui_mode', fallback='normal')
            else:
                self.ui_mode = 'normal'
        return self.ui_mode

class ChatClient:
    def __init__(self, server_config: ServerConfig, user_config: UserConfig):
        self.server_config = server_config
        self.user_config = user_config
        self.websocket = None
        self.user_id = None
        self.current_server = "printermake"  # Default server
        self.connected = False
        self.current_room = "general"
        self.rooms = {}
        self.messages = []
        self.encryption_manager = None
        self.user_public_keys = {}
        self.cyberpunk_mode = self.user_config.get_ui_mode() == "cyberpunk"
        self.is_running = True
        
    def setup_encryption(self):
        """Initialize encryption manager and handle key management"""
        username = self.user_config.get_username()
        if not username:
            return False
            
        self.encryption_manager = generate_new_encryption_manager()
        
        # Check for existing keys
        private_key_path = f"{username}_private.pem"
        public_key_path = f"{username}_public.pem"
        
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            # Load existing keys
            try:
                password = getpass.getpass("Enter password for your private key (or press Enter if none): ")
                if self.encryption_manager.load_keys(private_key_path, public_key_path, password or None):
                    if self.cyberpunk_mode:
                        print("🔑 KEYS LOADED - SECURE SESSION ESTABLISHED")
                    else:
                        print("✓ Loaded existing encryption keys.")
                else:
                    if self.cyberpunk_mode:
                        print("⚠️  KEY VERIFICATION FAILED - GENERATING NEW KEYS")
                    else:
                        print("✗ Failed to load existing keys. Generating new ones...")
                    self.encryption_manager.generate_keypair()
                    password = getpass.getpass("Set a password to protect your private key (optional): ")
                    self.encryption_manager.save_keys(private_key_path, public_key_path, password or None)
            except:
                # Generate new keys if load fails
                if self.cyberpunk_mode:
                    print("⚡ GENERATING NEW CRYPTOGRAPHIC KEYS")
                else:
                    print("Generating new encryption keys...")
                self.encryption_manager.generate_keypair()
                password = getpass.getpass("Set a password to protect your private key (optional): ")
                self.encryption_manager.save_keys(private_key_path, public_key_path, password or None)
        else:
            # Generate new keys
            if self.cyberpunk_mode:
                print("⚡ INITIALIZING CRYPTOGRAPHIC SYSTEM")
            else:
                print("Generating new encryption keys...")
            self.encryption_manager.generate_keypair()
            password = getpass.getpass("Set a password to protect your private key (optional): ")
            self.encryption_manager.save_keys(private_key_path, public_key_path, password or None)
            if self.cyberpunk_mode:
                print("🛡️  ENCRYPTION KEYS SECURED")
            else:
                print("✓ New encryption keys generated and saved.")
        
        if self.cyberpunk_mode:
            print(f"🔐 FINGERPRINT: {self.encryption_manager.get_key_fingerprint()}")
        else:
            print(f"Your key fingerprint: {self.encryption_manager.get_key_fingerprint()}")
        return True
    
    def show_welcome(self):
        """Show welcome screen"""
        if self.cyberpunk_mode:
            print("\n" + "█"*80)
            print("██  ██ ███████ ██   ██ ██████  ███████ ██████  ██████  ███████")
            print(" ██ ██  ██      ██ ██  ██   ██ ██      ██   ██ ██   ██ ██")
            print("  ███   █████    ███   ██████  █████   ██████  ██████  ███████")
            print(" ██ ██  ██      ██ ██  ██   ██ ██      ██   ██ ██   ██      ██")
            print("██  ██ ███████ ██   ██ ██   ██ ███████ ██   ██ ██   ██ ███████")
            print("█"*80)
            print("🔮 STANDALONE CLI CHAT INTERFACE 🔮")
            print("█"*80)
            print("💡 Type 'help' for commands, 'ui' for themes, 'server' for connections")
            print("█"*80 + "\n")
        else:
            print("\n" + "="*60)
            print("PrinterMake - CLI Chat Interface")
            print("="*60)
            print("Type 'help' for commands")
            print("="*60 + "\n")
    
    def show_login_prompt(self):
        """Show login screen"""
        if self.cyberpunk_mode:
            print("🌟 FIRST TIME SETUP - DIGITAL IDENTITY CREATION")
            print("█" * 50)
        else:
            print("First time setup - Please login")
            print("-" * 40)
        
        while True:
            username = input("Enter your username: ").strip()
            if username:
                if re.match(r'^[a-zA-Z0-9_-]+$', username) and len(username) <= 20:
                    self.user_config.login(username)
                    if self.cyberpunk_mode:
                        print(f"✅ IDENTITY CONFIRMED: {username}")
                    else:
                        print(f"✓ Logged in as: {username}")
                    return True
                else:
                    if self.cyberpunk_mode:
                        print("❌ INVALID USERNAME FORMAT")
                    else:
                        print("✗ Invalid username. Use alphanumeric characters, underscore, or hyphen (max 20 chars)")
            else:
                if self.cyberpunk_mode:
                    print("❌ USERNAME REQUIRED")
                else:
                    print("✗ Username cannot be empty")
    
    def handle_server_commands(self, command, args):
        """Handle server management commands"""
        if command == "add":
            if len(args) < 2:
                print("Usage: server add <domain/ip> <servername>")
                return
            
            domain_or_ip = args[0]
            servername = args[1]
            
            # Validate servername
            if not re.match(r'^[a-zA-Z0-9_-]+$', servername):
                print("✗ Invalid servername. Use alphanumeric characters, underscore, or hyphen")
                return
            
            # Add server
            if self.server_config.add_server(servername, domain_or_ip):
                if self.cyberpunk_mode:
                    print(f"🗺️  SERVER ADDED: {servername} → {domain_or_ip}")
                else:
                    print(f"✓ Added server '{servername}' -> {domain_or_ip}")
            else:
                print("✗ Failed to add server")
        
        elif command == "list":
            servers = self.server_config.list_servers()
            if servers:
                if self.cyberpunk_mode:
                    print("📋 CONFIGURED SERVERS:")
                else:
                    print("Configured servers:")
                for name, config in servers.items():
                    current = " (current)" if name == self.current_server else ""
                    print(f"  {name}: {config['host']}:{config['port']}{current}")
            else:
                if self.cyberpunk_mode:
                    print("🗺️  NO SERVERS CONFIGURED")
                else:
                    print("No servers configured. Use 'server add <domain/ip> <servername>' to add one.")
        
        elif command == "join":
            if not args:
                print("Usage: server join <servername>")
                return
            
            servername = args[0]
            server_info = self.server_config.get_server(servername)
            
            if server_info:
                self.current_server = servername
                if self.cyberpunk_mode:
                    print(f"🔗 CONNECTED TO: {servername} ({server_info['host']}:{server_info['port']})")
                else:
                    print(f"✓ Switched to server: {servername} ({server_info['host']}:{server_info['port']})")
            else:
                if self.cyberpunk_mode:
                    print(f"❌ SERVER NOT FOUND: {servername}")
                else:
                    print(f"✗ Server '{servername}' not found. Use 'server list' to see available servers.")
        
        elif command == "default":
            server_info = self.server_config.get_default_server()
            if self.cyberpunk_mode:
                print(f"🏠 DEFAULT SERVER: {self.current_server} ({server_info['host']}:{server_info['port']})")
            else:
                print(f"Default server: {self.current_server} ({server_info['host']}:{server_info['port']})")
        
        else:
            print(f"Unknown server command: {command}")
    
    def handle_ui_commands(self, command, args):
        """Handle UI commands"""
        if command in ["show", "on"]:
            self.cyberpunk_mode = True
            self.user_config.set_ui_mode("cyberpunk")
            self.show_cyberpunk_ui()
        elif command in ["hide", "off"]:
            self.cyberpunk_mode = False
            self.user_config.set_ui_mode("normal")
            self.show_normal_ui()
        else:
            print(f"Unknown UI command: {command}")
    
    def show_cyberpunk_ui(self):
        """Show Discord-like cyberpunk UI"""
        # Try to use Unicode characters, fallback to ASCII on Windows
        try:
            print("\n" + "█"*80)
            print("█" + " " * 78 + "█")
            print("█" + "  🟣 PRINTERMAKE CYBERPUNK INTERFACE  ".center(76) + "  █")
            print("█" + "  🔐 Secure • ⚡ Fast • 🎮 Gaming  ".center(76) + "  █")
            print("█" + " " * 78 + "█")
            print("█" + "-" * 78 + "█")
            print("█" + "  📱 SERVERS    💬 CHANNELS    🔧 SETTINGS    👤 PROFILE  ".center(76) + "  █")
            print("█" + "-" * 78 + "█")
            print("█" + " " * 78 + "█")
            print("█" + "  #general  🟢 Connected  ".ljust(76) + "  █")
            print("█" + "  📊 12 Online Users".ljust(76) + "  █")
            print("█" + " " * 78 + "█")
            print("█" + "  💬 " + "Welcome to PrinterMake Cyberpunk!".ljust(72) + "  █")
            print("█" + "  👤 " + "System".ljust(25) + " ⏰ Now".ljust(25) + " 🔐".ljust(20) + "  █")
            print("█" + " " * 78 + "█")
            print("█" + "  💬 " + "Type your message here...".ljust(72) + "  █")
            print("█" + "  " + "─" * 75 + "  █")
            print("█" + "  🎮 Gaming    💻 Tech    🎨 Art    🎵 Music    📚 General  ".ljust(76) + "  █")
            print("█" + " " * 78 + "█")
            print("█"*80)
            print("CYBERPUNK MODE ACTIVATED")
            print("Use 'ui off' to return to normal mode")
            print("Current server: " + self.current_server)
            print()
        except UnicodeEncodeError:
            # Fallback to ASCII-only display
            print("\n" + "#"*80)
            print("| PURPLE PRINTERMAKE CYBERPUNK INTERFACE |".center(76))
            print("| SECURE • FAST • GAMING |".center(76))
            print("| " + "-" * 76 + " |")
            print("|  [SERVERS] [CHANNELS] [SETTINGS] [PROFILE]  |".center(76))
            print("| " + "-" * 76 + " |")
            print("|  #general  [CONNECTED]  |".ljust(78) + "|")
            print("|  12 Online Users |".ljust(78) + "|")
            print("| " + "-" * 76 + " |")
            print("|  [MESSAGE] Welcome to PrinterMake Cyberpunk! |")
            print("|  [USER] System  [TIME] Now  [SECURE] |")
            print("| " + "-" * 76 + " |")
            print("|  [INPUT] Type your message here... |")
            print("| " + "-" * 76 + " |")
            print("|  [GAMING] [TECH] [ART] [MUSIC] [GENERAL]  |".ljust(78) + "|")
            print("#"*80)
            print("CYBERPUNK MODE ACTIVATED")
            print("Use 'ui off' to return to normal mode")
            print("Current server: " + self.current_server)
            print()
    
    def show_normal_ui(self):
        """Show clean normal UI"""
        print("\n" + "="*60)
        print("PrinterMake - Normal Interface")
        print("="*60)
        print("NORMAL MODE ACTIVATED")
        print("Use 'ui on' to enable cyberpunk mode")
        print("Current server: " + self.current_server)
        print()
    
    def show_status(self):
        """Show client status"""
        if self.cyberpunk_mode:
            print("\n" + "█"*60)
            print("📊 SYSTEM STATUS REPORT")
            print("█"*60)
        else:
            print("\n--- Client Status ---")
        
        server_info = self.server_config.get_server(self.current_server)
        print(f"Server: {self.current_server}")
        if server_info:
            print(f"Address: {server_info['host']}:{server_info['port']}")
        
        username = self.user_config.get_username()
        print(f"User: {username or 'Not logged in'}")
        print(f"UI: {'CYBERPUNK' if self.cyberpunk_mode else 'NORMAL'}")
        print(f"Status: {'ONLINE' if self.connected else 'OFFLINE'}")
        
        if self.cyberpunk_mode:
            print("█"*60 + "\n")
        else:
            print("---" * 20 + "\n")
    
    def show_help(self):
        """Show help information"""
        if self.cyberpunk_mode:
            print("\n" + "█"*80)
            print("🆘 COMMAND REFERENCE MANUAL")
            print("█"*80)
            print("🗺️  SERVER MANAGEMENT:")
            print("  server add <domain/ip> <servername>  - Register new server")
            print("  server join <servername>              - Switch server connection")
            print("  server list                           - Display all servers")
            print("  server default                        - Show default configuration")
            print()
            print("INTERFACE COMMANDS:")
            print("  ui show / ui on                       - Discord-like cyberpunk UI")
            print("  ui hide / ui off                      - Clean normal interface")
            print()
            print("CHAT COMMANDS:")
            print("  /status                               - System status report")
            print("  /help                                 - Display this help")
            print("  /clear                                - Clear terminal")
            print("  /quit                                 - Exit application")
            print("  /rooms                                - List available rooms")
            print("  /join <room>                          - Enter specified room")
            print()
            print("QUICK EXAMPLES:")
            print("  server join printermake                - Connect to your server")
            print("  ui on                                  - Enable cyberpunk UI")
            print("  help                                   - Show this help")
            print("="*80 + "\n")
        else:
            print("\nAvailable Commands:")
            print()
            print("SERVER MANAGEMENT:")
            print("  server add <domain/ip> <servername>  - Add a new server")
            print("  server join <servername>              - Switch to a server")
            print("  server list                           - List all servers")
            print("  server default                        - Show default server")
            print()
            print("UI COMMANDS:")
            print("  ui show / ui on                       - Enable Discord-like cyberpunk UI")
            print("  ui hide / ui off                      - Disable cyberpunk UI")
            print()
            print("CHAT COMMANDS:")
            print("  /status                               - Show connection status")
            print("  /help                                 - Show this help")
            print("  /clear                                - Clear screen")
            print("  /quit                                 - Exit client")
            print("  /rooms                                - List available rooms")
            print("  /join <room>                          - Join a room")
            print()
            print("QUICK START:")
            print("  server join printermake                - Connect to your server")
            print("  ui on                                  - Enable cyberpunk UI")
            print()
    
    def handle_local_chat(self, message):
        """Handle local chat messages (when not connected to server)"""
        if self.cyberpunk_mode:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"\n[{timestamp}] 💬 LOCAL CHAT: {message}")
            print("🔗 Connect to server with 'server join <servername>' to send messages")
        else:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"\n[{timestamp}] Local: {message}")
            print("Connect to server with 'server join <servername>' to send messages")
    
    def run_interactive(self):
        """Run continuous interactive chat mode like Gemini CLI"""
        # First time setup if needed
        if not self.user_config.is_logged_in():
            self.show_login_prompt()
        
        # Setup encryption (if not already done)
        if not self.encryption_manager:
            self.setup_encryption()
        
        # Show welcome screen
        self.show_welcome()
        
        # Main interactive loop - runs until Ctrl+C
        while self.is_running:
            try:
                username = self.user_config.get_username()
                if not username:
                    if self.cyberpunk_mode:
                        print("❌ NO IDENTITY - LOGIN REQUIRED")
                        self.show_login_prompt()
                        continue
                    else:
                        print("No username found. Please login first.")
                        if not self.show_login_prompt():
                            break
                        continue
                
                # Dynamic prompt that changes based on connection status
                if self.cyberpunk_mode:
                    status = "ONLINE" if self.connected else "OFFLINE"
                    prompt = f"[MESSAGE] {username}@{self.current_server} [{status}]_$ "
                else:
                    status = "connected" if self.connected else "offline"
                    prompt = f"{username}@{self.current_server} ({status}):~$ "
                
                user_input = input(prompt).strip()
                
                if not user_input:
                    continue
                
                # Handle commands
                if user_input.startswith('server '):
                    parts = user_input[7:].split()
                    if parts:
                        self.handle_server_commands(parts[0], parts[1:])
                elif user_input.startswith('ui '):
                    parts = user_input[3:].split()
                    if parts:
                        self.handle_ui_commands(parts[0], parts[1:])
                elif user_input in ['/help', 'help']:
                    self.show_help()
                elif user_input in ['/status', 'status']:
                    self.show_status()
                elif user_input in ['/clear', 'clear']:
                    os.system('cls' if os.name == 'nt' else 'clear')
                    self.show_welcome()
                elif user_input in ['/quit', '/exit', 'quit', 'exit']:
                    if self.cyberpunk_mode:
                        print("🛑 SHUTTING DOWN...")
                    else:
                        print("Goodbye!")
                    break
                else:
                    # Handle chat messages - work offline
                    if self.connected:
                        if self.cyberpunk_mode:
                            print(f"📡 SENDING: {user_input} (to {self.current_room})")
                        else:
                            print(f"Sending message to {self.current_room}: {user_input}")
                        # TODO: Implement actual message sending to server
                    else:
                        # Work offline like a local chat
                        self.handle_local_chat(user_input)
                        
            except KeyboardInterrupt:
                if self.cyberpunk_mode:
                    print("\n🛑 INTERRUPT DETECTED - SHUTTING DOWN...")
                else:
                    print("\nExiting...")
                break
            except EOFError:
                if self.cyberpunk_mode:
                    print("\n🛑 EOF DETECTED - SHUTTING DOWN...")
                else:
                    print("\nExiting...")
                break
            except Exception as e:
                if self.cyberpunk_mode:
                    print(f"❌ SYSTEM ERROR: {e}")
                else:
                    print(f"Error: {e}")
                time.sleep(1)  # Brief pause before continuing

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="PrinterMake - Standalone CLI Chat Interface")
    parser.add_argument("--cyberpunk", action="store_true", help="Start in cyberpunk mode")
    
    args = parser.parse_args()
    
    # Initialize configs
    server_config = ServerConfig()
    user_config = UserConfig()
    
    client = ChatClient(server_config, user_config)
    
    # Set initial UI mode
    if args.cyberpunk:
        client.cyberpunk_mode = True
        user_config.set_ui_mode("cyberpunk")
    
    try:
        client.run_interactive()
    except KeyboardInterrupt:
        print("\nClient stopped by user")
    except Exception as e:
        print(f"Client error: {e}")

if __name__ == "__main__":
    main()
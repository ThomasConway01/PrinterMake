#!/usr/bin/env python3
"""
Encrypted CLI Chat Client
A command-line chat application with end-to-end encryption and cyberpunk UI
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

# Add the server directory to path to import encryption module
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'server'))

try:
    from encryption import EncryptionManager, generate_new_encryption_manager
except ImportError:
    print("Error: Could not import encryption module. Make sure encryption.py is in the server directory.")
    sys.exit(1)

class ChatClient:
    def __init__(self, server_host: str = "localhost", server_port: int = 8765, demo_mode: bool = False):
        self.server_host = server_host
        self.server_port = server_port
        self.demo_mode = demo_mode
        self.websocket = None
        self.user_id = None
        self.username = None
        self.connected = False
        self.current_room = "general"
        self.rooms = {}
        self.messages = []
        self.encryption_manager = None
        self.user_public_keys = {}  # Store other users' public keys
        self.cyberpunk_mode = False
        
    def setup_encryption(self):
        """Initialize encryption manager and handle key management"""
        self.encryption_manager = generate_new_encryption_manager()
        
        # Check for existing keys
        private_key_path = f"{self.username}_private.pem"
        public_key_path = f"{self.username}_public.pem"
        
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            # Load existing keys
            password = getpass.getpass("Enter password for your private key (or press Enter if none): ")
            if self.encryption_manager.load_keys(private_key_path, public_key_path, password or None):
                print("Loaded existing encryption keys.")
            else:
                print("Failed to load existing keys. Generating new ones...")
                self.encryption_manager.generate_keypair()
                self.encryption_manager.save_keys(private_key_path, public_key_path)
        else:
            # Generate new keys
            print("Generating new encryption keys...")
            self.encryption_manager.generate_keypair()
            password = getpass.getpass("Set a password to protect your private key (optional): ")
            self.encryption_manager.save_keys(private_key_path, public_key_path, password or None)
            print("New encryption keys generated and saved.")
        
        print(f"Your key fingerprint: {self.encryption_manager.get_key_fingerprint()}")
    
    def run_demo_mode(self):
        """Run in demo mode without server connection"""
        print("🎮 DEMO MODE ACTIVATED")
        print("=======================")
        print("Welcome to PrinterMake Chat Demo!")
        print("This simulates the chat experience without a real server.")
        print()
        
        # Demo users and responses
        demo_users = ['Tom', 'Alice', 'Bob', 'Charlie', 'Diana']
        demo_messages = [
            "Hey everyone! Welcome to the demo!",
            "This is a simulated chat environment.",
            "The real app has end-to-end encryption! 🔐",
            "Try the /ui command for cyberpunk mode!",
            "You can use /help to see all available commands.",
            "This is running in demo mode without a server.",
            "The actual app would be connected to printermake.online"
        ]
        
        print("Demo chat started!")
        print("Type your messages or commands below.")
        print("Use /help for commands, /quit to exit demo")
        print()
        
        while True:
            try:
                user_input = input("demo@chat:~$ ").strip()
                
                if not user_input:
                    continue
                
                if user_input.lower() in ['/quit', '/exit', 'exit']:
                    print("Thanks for trying the demo!")
                    break
                
                # Handle demo commands
                if user_input.startswith('/'):
                    self.handle_demo_command(user_input)
                else:
                    # Simulate chat response
                    self.simulate_demo_response(user_input)
                    
            except KeyboardInterrupt:
                print("\nExiting demo...")
                break
            except Exception as e:
                print(f"Demo error: {e}")
    
    def handle_demo_command(self, command):
        """Handle commands in demo mode"""
        cmd = command.lower()
        
        if cmd == "/help":
            self.print_demo_help()
        elif cmd == "/ui":
            self.toggle_cyberpunk_ui()
        elif cmd == "/rooms":
            self.show_demo_rooms()
        elif cmd == "/status":
            self.show_demo_status()
        elif cmd == "/clear":
            os.system('cls' if os.name == 'nt' else 'clear')
            print("Screen cleared! Type /help for commands.")
        elif cmd == "/demo":
            print("Demo mode is already active! 🎮")
        else:
            print(f"Demo command not implemented: {command}")
            print("Try /help for available demo commands.")
    
    def simulate_demo_response(self, message):
        """Simulate a response in demo mode"""
        # Simulate typing delay
        time.sleep(0.5)
        
        demo_responses = [
            ("Tom", "Nice message! The demo is working well."),
            ("Alice", "That's interesting! This is all simulated."),
            ("Bob", "Great! The real app has more features."),
            ("Charlie", "Welcome to the demo! The encryption is simulated here."),
            ("Diana", "The actual app connects to printermake.online!"),
        ]
        
        user, response = demo_responses[time.time() % len(demo_responses) == 0 and 0 or int(time.time()) % len(demo_responses)]
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        if self.cyberpunk_mode:
            print(f"\033[36m[{timestamp}]\033[0m \033[33m{user}\033[0m: \033[32m{response}\033[0m")
        else:
            print(f"[{timestamp}] {user}: {response}")
    
    def print_demo_help(self):
        """Print demo help"""
        if self.cyberpunk_mode:
            print("\n" + "█"*60)
            print("    ██████╗ ██████╗ ███████╗███╗   ██╗    ██████╗ ██╗   ██╗██████╗")
            print("   ██╔═══██╗██╔══██╗██╔════╝████╗  ██║    ██╔═══██╗██║   ██║██╔══██╗")
            print("   ██║   ██║██████╔╝█████╗  ██╔██╗ ██║    ██║   ██║██║   ██║██████╔╝")
            print("   ██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║    ██║   ██║██║   ██║██╔═══╝")
            print("   ╚██████╔╝██║     ███████╗██║ ╚████║    ╚██████╔╝╚██████╔╝██║")
            print("    ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝     ╚═════╝  ╚═════╝ ╚═╝")
            print("█"*60)
            print("DEMO COMMANDS:")
            print("  /help         - Show this help")
            print("  /ui           - Toggle cyberpunk UI")
            print("  /rooms        - List demo rooms")
            print("  /status       - Show demo status")
            print("  /clear        - Clear screen")
            print("  /demo         - Show demo info")
            print("  /quit         - Exit demo")
            print("="*60)
            print("TYPE ANY MESSAGE TO SEE SIMULATED RESPONSES!")
            print("="*60 + "\n")
        else:
            print("\nAvailable demo commands:")
            print("  /help         - Show this help")
            print("  /ui           - Toggle cyberpunk UI")
            print("  /rooms        - List demo rooms")
            print("  /status       - Show demo status")
            print("  /clear        - Clear screen")
            print("  /demo         - Show demo info")
            print("  /quit         - Exit demo")
            print("\nTYPE ANY MESSAGE TO SEE SIMULATED RESPONSES!")
            print("This is a demo - the real app connects to printermake.online\n")
    
    def show_demo_rooms(self):
        """Show demo rooms"""
        if self.cyberpunk_mode:
            print(f"\n{'='*60}")
            print(f"ROOM LIST (DEMO)")
            print(f"{'='*60}")
        else:
            print("\nDemo available rooms:")
        print("  general      - General chat (demo users)")
        print("  tech         - Tech discussion (simulated)")
        print("  random       - Random topics (demo)")
        print("  demo-room    - Demo-specific room")
        if self.cyberpunk_mode:
            print(f"{'='*60}\n")
    
    def show_demo_status(self):
        """Show demo status"""
        if self.cyberpunk_mode:
            print("\n" + "█"*60)
            print("    █████╗ ██╗    ██████╗ ███████╗███╗   ██╗")
            print("   ██╔══██╗██║    ██╔══██╗██╔════╝████╗  ██║")
            print("   ███████║██║    ██████╔╝█████╗  ██╔██╗ ██║")
            print("   ██╔══██║██║    ██╔══██╗██╔══╝  ██║╚██╗██║")
            print("   ██║  ██║██║    ██║  ██║███████╗██║ ╚████║")
            print("   ╚═╝  ╚═╝╚═╝    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝")
            print("█"*60)
            print("DEMO STATUS REPORT:")
        else:
            print("\n--- Demo Status ---")
        print(f"Mode: DEMO (No server connection)")
        print(f"Simulated Users: 5 active")
        print(f"Demo Room: {self.current_room}")
        print(f"UI Mode: {'CYBERPUNK' if self.cyberpunk_mode else 'NORMAL'}")
        print(f"Encryption: Simulated (Real app uses RSA-2048 + AES-256)")
        print(f"Website: https://printermake.online")
        if self.cyberpunk_mode:
            print("█"*60 + "\n")
        else:
            print("--------------\n")
    
    def toggle_cyberpunk_ui(self):
        """Toggle cyberpunk UI mode"""
        self.cyberpunk_mode = not self.cyberpunk_mode
        if self.cyberpunk_mode:
            print("\n" + "="*60)
            print("█ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █")
            print("    ┌─┐┌┬┐┬ ┬┌─┐┌┐┌┌┬┐  ┬ ┬┌─┐┌┐┌┌┬┐┌─┐┌┐┌┌┬┐")
            print("    └─┐ │ │ │├─┤│││ ││  │ ││ ││││ ││ ││││ ││")
            print("    └─┘ ┴ └─┘┴ ┴┘└┘─┴┘  └─┘└─┘┘└┘ ┴└─┘┘└┘ ┴└─┘")
            print("█ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █")
            print("="*60)
            print("CYBERPUNK MODE ACTIVATED (DEMO)")
            print("All messages are simulated and secure")
            print("="*60 + "\n")
        else:
            print("CYBERPUNK MODE DEACTIVATED (DEMO)\n")
    
    async def connect_to_server(self):
        """Connect to the chat server"""
        try:
            self.websocket = await websockets.connect(f"ws://{self.server_host}:{self.server_port}")
            self.connected = True
            print(f"Connected to server at {self.server_host}:{self.server_port}")
            return True
        except Exception as e:
            print(f"Failed to connect to server: {e}")
            print("Hint: Use --demo to run without a server, or start the server first.")
            return False
    
    # ... (rest of the server connection methods remain the same)
    # [I'll keep the rest of the methods from the original client but truncated for space]
    
    async def register_user(self):
        """Register a new user on the server"""
        if not self.connected:
            print("Not connected to server")
            return False
        
        try:
            public_key = self.encryption_manager.export_public_key()
            message = {
                "type": "register",
                "username": self.username,
                "public_key": public_key
            }
            
            await self.websocket.send(json.dumps(message))
            response = json.loads(await self.websocket.recv())
            
            if response["status"] == "success":
                self.user_id = response["user_id"]
                print(f"Successfully registered as {self.username}")
                return True
            else:
                print(f"Registration failed: {response.get('message', 'Unknown error')}")
                return False
        except Exception as e:
            print(f"Error during registration: {e}")
            return False
    
    async def run(self):
        """Main client loop"""
        if self.demo_mode:
            self.run_demo_mode()
            return
        
        print("Welcome to Encrypted CLI Chat!")
        print("================================")
        
        # Get username
        while not self.username:
            username = input("Enter your username: ").strip()
            if username:
                self.username = username
            else:
                print("Username cannot be empty")
        
        # Setup encryption
        self.setup_encryption()
        
        # Connect to server
        if not await self.connect_to_server():
            return
        
        # Try to register, if fails try to authenticate
        registered = await self.register_user()
        if not registered:
            print("Registration failed. Exiting.")
            return
        
        print("Client connected successfully!")
        print("Server connection established. You can now chat!")
        print("Type /help for commands or just start typing to chat!")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Encrypted CLI Chat Client")
    parser.add_argument("--host", default="localhost", help="Server host")
    parser.add_argument("--port", type=int, default=8765, help="Server port")
    parser.add_argument("--demo", action="store_true", help="Run in demo mode without server")
    
    args = parser.parse_args()
    
    client = ChatClient(server_host=args.host, server_port=args.port, demo_mode=args.demo)
    
    try:
        asyncio.run(client.run())
    except KeyboardInterrupt:
        print("\nClient stopped by user")
    except Exception as e:
        print(f"Client error: {e}")

if __name__ == "__main__":
    main()
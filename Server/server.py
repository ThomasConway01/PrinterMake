#!/usr/bin/env python3
"""
PrinterMake - Encrypted CLI Chat Server
A production-ready WebSocket server with advanced security features
"""

import asyncio
import websockets
import json
import logging
import os
import sqlite3
import hashlib
import secrets
import ssl
import ipaddress
import re
from datetime import datetime, timedelta
from typing import Dict, Set, List, Optional
from dataclasses import dataclass
import base64
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class User:
    username: str
    user_id: str
    public_key: str
    connected: bool = False
    last_seen: datetime = None
    created_at: datetime = None

@dataclass
class Message:
    message_id: str
    sender_id: str
    room_id: str
    encrypted_content: str
    timestamp: str
    message_type: str = "message"

class SecurityManager:
    """Advanced security features for the chat server"""
    
    def __init__(self):
        self.blocked_ips = set()
        self.rate_limits = {}  # IP -> {count, reset_time}
        self.failed_connections = {}  # IP -> count
        self.suspicious_patterns = []
        
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        return ip in self.blocked_ips
    
    def rate_limit_check(self, ip: str, max_requests: int = 100, window: int = 60) -> bool:
        """Check rate limiting"""
        now = time.time()
        
        if ip not in self.rate_limits:
            self.rate_limits[ip] = {"count": 1, "reset_time": now + window}
            return True
        
        if now > self.rate_limits[ip]["reset_time"]:
            self.rate_limits[ip] = {"count": 1, "reset_time": now + window}
            return True
        
        self.rate_limits[ip]["count"] += 1
        return self.rate_limits[ip]["count"] <= max_requests
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is from private network"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return (ip_obj.is_private or 
                   ip_obj.is_loopback or 
                   ip_obj.is_multicast or
                   ip_obj.is_reserved)
        except:
            return True
    
    def validate_username(self, username: str) -> bool:
        """Validate username for security"""
        if not username or len(username) > 20:
            return False
        
        # Only allow alphanumeric, underscores, and hyphens
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False
        
        # Check for suspicious patterns
        suspicious = ['admin', 'root', 'system', 'bot', 'hack', 'script']
        if any(s in username.lower() for s in suspicious):
            return False
        
        return True
    
    def validate_public_key(self, public_key: str) -> bool:
        """Validate public key format"""
        if not public_key:
            return False
        
        try:
            # Should be base64 encoded and reasonable length
            decoded = base64.b64decode(public_key.encode('utf-8'))
            return 200 < len(decoded) < 1000  # RSA public key size range
        except:
            return False

class PrinterMakeServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8765):
        self.host = host
        self.port = port
        self.clients: Dict[str, websockets.WebSocketServerProtocol] = {}
        self.users: Dict[str, User] = {}
        self.rooms: Dict[str, Set[str]] = {"general": set(), "main": set()}
        self.messages: List[Message] = []
        self.security = SecurityManager()
        
        # Generic configuration for self-hosting
        self.db_path = "chat_data.db"  # Generic database name
        self.admin_password = os.environ.get('CHAT_ADMIN', secrets.token_hex(16))
        self.jwt_secret = os.environ.get('CHAT_JWT_SECRET', secrets.token_hex(32))
        self.init_database()
        
    def init_database(self):
        """Initialize secure SQLite database"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = conn.cursor()
        
        # Enable WAL mode for better concurrency
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA cache_size=1000")
        cursor.execute("PRAGMA temp_store=memory")
        
        # Users table with security fields
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                public_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                login_attempts INTEGER DEFAULT 0,
                ip_address TEXT,
                user_agent TEXT
            )
        ''')
        
        # Messages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                message_id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                room_id TEXT NOT NULL,
                encrypted_content TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users (user_id)
            )
        ''')
        
        # Rooms table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rooms (
                room_id TEXT PRIMARY KEY,
                created_by TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_private BOOLEAN DEFAULT FALSE,
                max_users INTEGER DEFAULT 100,
                FOREIGN KEY (created_by) REFERENCES users (user_id)
            )
        ''')
        
        # Security logs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                event_type TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Secure database initialized")
    
    def generate_user_id(self, username: str) -> str:
        """Generate a unique user ID with security"""
        timestamp = str(int(time.time()))
        random_part = secrets.token_hex(8)
        return hashlib.sha256(f"{username}{timestamp}{random_part}".encode()).hexdigest()[:16]
    
    def generate_message_id(self) -> str:
        """Generate a unique message ID"""
        return f"msg_{secrets.token_hex(12)}"
    
    def log_security_event(self, ip: str, event_type: str, details: str):
        """Log security events"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO security_logs (ip_address, event_type, details) VALUES (?, ?, ?)",
            (ip, event_type, details)
        )
        conn.commit()
        conn.close()
    
    async def register_user(self, username: str, public_key: str, client_ip: str) -> dict:
        """Register a new user with security checks"""
        try:
            # Security validations
            if self.security.is_ip_blocked(client_ip):
                self.log_security_event(client_ip, "BLOCKED_IP", f"Registration attempt from blocked IP")
                return {"status": "error", "message": "Access denied"}
            
            if not self.security.rate_limit_check(client_ip):
                self.log_security_event(client_ip, "RATE_LIMIT", "Registration rate limit exceeded")
                return {"status": "error", "message": "Too many requests"}
            
            if not self.security.validate_username(username):
                self.log_security_event(client_ip, "INVALID_USERNAME", f"Invalid username: {username}")
                return {"status": "error", "message": "Invalid username format"}
            
            if not self.security.validate_public_key(public_key):
                self.log_security_event(client_ip, "INVALID_KEY", "Invalid public key format")
                return {"status": "error", "message": "Invalid encryption key"}
            
            # Check for existing user
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                conn.close()
                return {"status": "error", "message": "Username already exists"}
            
            # Create new user
            user_id = self.generate_user_id(username)
            now = datetime.now()
            user = User(
                username=username, 
                user_id=user_id, 
                public_key=public_key,
                last_seen=now,
                created_at=now
            )
            
            # Store in database
            cursor.execute('''
                INSERT INTO users (user_id, username, public_key, last_seen, created_at) 
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, username, public_key, now, now))
            conn.commit()
            conn.close()
            
            # Store in memory
            self.users[user_id] = user
            
            logger.info(f"User registered: {username} ({user_id}) from {client_ip}")
            return {
                "status": "success",
                "user_id": user_id,
                "username": username
            }
        except Exception as e:
            logger.error(f"Error registering user: {e}")
            return {"status": "error", "message": "Registration failed"}
    
    async def authenticate_user(self, username: str, public_key: str, client_ip: str) -> dict:
        """Authenticate an existing user with security checks"""
        try:
            if self.security.is_ip_blocked(client_ip):
                self.log_security_event(client_ip, "BLOCKED_IP", f"Auth attempt from blocked IP")
                return {"status": "error", "message": "Access denied"}
            
            # Find user in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT user_id, public_key, is_active, login_attempts FROM users WHERE username = ?",
                (username,)
            )
            result = cursor.fetchone()
            
            if not result:
                conn.close()
                self.log_security_event(client_ip, "AUTH_FAILED", f"User not found: {username}")
                return {"status": "error", "message": "User not found"}
            
            user_id, stored_public_key, is_active, login_attempts = result
            
            if not is_active:
                conn.close()
                self.log_security_event(client_ip, "AUTH_FAILED", f"User account disabled: {username}")
                return {"status": "error", "message": "Account disabled"}
            
            if login_attempts >= 5:  # Lock account after 5 failed attempts
                conn.close()
                self.log_security_event(client_ip, "AUTH_FAILED", f"Account locked: {username}")
                return {"status": "error", "message": "Account temporarily locked"}
            
            # Verify public key
            if stored_public_key != public_key:
                cursor.execute("UPDATE users SET login_attempts = login_attempts + 1 WHERE username = ?", (username,))
                conn.commit()
                conn.close()
                self.log_security_event(client_ip, "AUTH_FAILED", f"Invalid key for user: {username}")
                return {"status": "error", "message": "Authentication failed"}
            
            # Reset login attempts on successful auth
            cursor.execute("UPDATE users SET login_attempts = 0, last_seen = ? WHERE username = ?", 
                          (datetime.now(), username))
            conn.commit()
            conn.close()
            
            # Update user status
            if user_id in self.users:
                self.users[user_id].connected = True
                self.users[user_id].last_seen = datetime.now()
            else:
                self.users[user_id] = User(
                    username=username,
                    user_id=user_id,
                    public_key=public_key,
                    connected=True,
                    last_seen=datetime.now()
                )
            
            logger.info(f"User authenticated: {username} ({user_id}) from {client_ip}")
            return {
                "status": "success",
                "user_id": user_id,
                "username": username
            }
        except Exception as e:
            logger.error(f"Error authenticating user: {e}")
            return {"status": "error", "message": "Authentication failed"}
    
    async def store_message(self, message: Message):
        """Store message with validation"""
        try:
            # Sanitize room_id
            if not re.match(r'^[a-zA-Z0-9_-]+$', message.room_id) or len(message.room_id) > 50:
                return
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO messages (message_id, sender_id, room_id, encrypted_content) VALUES (?, ?, ?, ?)",
                (message.message_id, message.sender_id, message.room_id, message.encrypted_content)
            )
            conn.commit()
            conn.close()
            self.messages.append(message)
        except Exception as e:
            logger.error(f"Error storing message: {e}")
    
    async def get_room_history(self, room_id: str, limit: int = 50) -> List[dict]:
        """Get message history for a room"""
        try:
            # Sanitize room_id
            if not re.match(r'^[a-zA-Z0-9_-]+$', room_id) or len(room_id) > 50:
                return []
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT m.message_id, m.sender_id, u.username, m.encrypted_content, m.timestamp
                FROM messages m
                JOIN users u ON m.sender_id = u.user_id
                WHERE m.room_id = ?
                ORDER BY m.timestamp DESC
                LIMIT ?
            ''', (room_id, limit))
            
            history = []
            for row in cursor.fetchall():
                message_id, sender_id, username, encrypted_content, timestamp = row
                history.append({
                    "message_id": message_id,
                    "sender_id": sender_id,
                    "username": username,
                    "encrypted_content": encrypted_content,
                    "timestamp": timestamp
                })
            
            conn.close()
            return list(reversed(history))
        except Exception as e:
            logger.error(f"Error getting room history: {e}")
            return []
    
    async def create_room(self, room_id: str, creator_id: str) -> dict:
        """Create a new room with validation"""
        if not re.match(r'^[a-zA-Z0-9_-]+$', room_id) or len(room_id) > 50:
            return {"status": "error", "message": "Invalid room name"}
        
        if room_id in self.rooms:
            return {"status": "error", "message": "Room already exists"}
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO rooms (room_id, created_by) VALUES (?, ?)",
                (room_id, creator_id)
            )
            conn.commit()
            conn.close()
            
            self.rooms[room_id] = set()
            logger.info(f"Room created: {room_id} by {creator_id}")
            return {"status": "success", "room_id": room_id}
        except Exception as e:
            logger.error(f"Error creating room: {e}")
            return {"status": "error", "message": "Failed to create room"}
    
    async def join_room(self, user_id: str, room_id: str) -> dict:
        """Join a room with security checks"""
        # Sanitize room_id
        if not re.match(r'^[a-zA-Z0-9_-]+$', room_id) or len(room_id) > 50:
            return {"status": "error", "message": "Invalid room name"}
        
        if room_id not in self.rooms:
            return {"status": "error", "message": "Room not found"}
        
        # Check room capacity
        if len(self.rooms[room_id]) >= 100:  # Max users per room
            return {"status": "error", "message": "Room is full"}
        
        self.rooms[room_id].add(user_id)
        logger.info(f"User {user_id} joined room {room_id}")
        return {"status": "success", "room_id": room_id}
    
    async def broadcast_to_room(self, room_id: str, message: dict, exclude_user: str = None):
        """Broadcast message to all users in a room"""
        if room_id not in self.rooms:
            return
        
        for user_id in self.rooms[room_id]:
            if user_id != exclude_user and user_id in self.clients:
                try:
                    await self.clients[user_id].send(json.dumps(message))
                except Exception as e:
                    logger.error(f"Error sending message to {user_id}: {e}")
    
    async def handle_client(self, websocket):
        """Handle new client connection with security (fixed WebSocket method)"""
        client_ip = websocket.remote_address[0]
        
        try:
            # Security checks
            if self.security.is_ip_blocked(client_ip):
                logger.warning(f"Blocked connection attempt from {client_ip}")
                return
            
            if not self.security.rate_limit_check(client_ip):
                logger.warning(f"Rate limit exceeded for {client_ip}")
                return
            
            logger.info(f"New connection from {client_ip}")
            
            async for message in websocket:
                try:
                    data = json.loads(message)
                    await self.handle_message(websocket, data, client_ip)
                except json.JSONDecodeError:
                    await websocket.send(json.dumps({
                        "status": "error",
                        "message": "Invalid JSON"
                    }))
                except Exception as e:
                    logger.error(f"Error handling message from {client_ip}: {e}")
                    await websocket.send(json.dumps({
                        "status": "error",
                        "message": "Internal server error"
                    }))
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Client disconnected: {client_ip}")
        except Exception as e:
            logger.error(f"Connection error with {client_ip}: {e}")
        finally:
            # Clean up
            client_id = getattr(websocket, 'user_id', None)
            if client_id and client_id in self.clients:
                del self.clients[client_id]
                if client_id in self.users:
                    self.users[client_id].connected = False
    
    async def handle_message(self, websocket, data: dict, client_ip: str):
        """Handle incoming message from client"""
        try:
            message_type = data.get("type")
            
            if message_type == "register":
                response = await self.register_user(
                    data.get("username", ""),
                    data.get("public_key", ""),
                    client_ip
                )
                await websocket.send(json.dumps(response))
                
            elif message_type == "authenticate":
                response = await self.authenticate_user(
                    data.get("username", ""),
                    data.get("public_key", ""),
                    client_ip
                )
                if response["status"] == "success":
                    # Store user association with websocket
                    websocket.user_id = response["user_id"]
                await websocket.send(json.dumps(response))
                
            elif message_type == "list_rooms":
                rooms = [{"room_id": room_id, "user_count": len(users)} 
                        for room_id, users in self.rooms.items()]
                await websocket.send(json.dumps({
                    "status": "success",
                    "rooms": rooms
                }))
                
            elif message_type == "create_room":
                user_id = data.get("user_id")
                room_id = data.get("room_id", "")
                response = await self.create_room(room_id, user_id)
                await websocket.send(json.dumps(response))
                
            elif message_type == "join_room":
                user_id = data.get("user_id")
                room_id = data.get("room_id", "")
                response = await self.join_room(user_id, room_id)
                
                if response["status"] == "success":
                    history = await self.get_room_history(room_id)
                    await websocket.send(json.dumps({
                        "type": "room_history",
                        "room_id": room_id,
                        "messages": history
                    }))
                
                await websocket.send(json.dumps(response))
                
            elif message_type == "message":
                user_id = data.get("user_id")
                room_id = data.get("room_id", "")
                content = data.get("content", "")
                
                # Sanitize content
                if len(content) > 2000:  # Max message length
                    await websocket.send(json.dumps({
                        "status": "error",
                        "message": "Message too long"
                    }))
                    return
                
                # Create and store message
                message = Message(
                    message_id=self.generate_message_id(),
                    sender_id=user_id,
                    room_id=room_id,
                    encrypted_content=content,
                    timestamp=datetime.now().isoformat()
                )
                
                await self.store_message(message)
                
                # Broadcast to room
                user = self.users.get(user_id)
                username = user.username if user else "Unknown"
                
                broadcast_message = {
                    "type": "message",
                    "message_id": message.message_id,
                    "sender_id": user_id,
                    "username": username,
                    "room_id": room_id,
                    "encrypted_content": content,
                    "timestamp": message.timestamp
                }
                
                await self.broadcast_to_room(room_id, broadcast_message)
                
            elif message_type == "connect":
                user_id = data.get("user_id")
                self.clients[user_id] = websocket
                websocket.user_id = user_id
                
                if user_id in self.users:
                    self.users[user_id].connected = True
                
                await websocket.send(json.dumps({
                    "status": "success",
                    "message": "Connected to secure chat server"
                }))
            
            else:
                await websocket.send(json.dumps({
                    "status": "error",
                    "message": "Unknown message type"
                }))
        except Exception as e:
            logger.error(f"Error in handle_message: {e}")
            await websocket.send(json.dumps({
                "status": "error",
                "message": "Server error"
            }))
    
    async def start(self):
        """Start the secure WebSocket chat server"""
        logger.info(f"🚀 Starting secure chat server on {self.host}:{self.port}")
        logger.info(f"👤 Admin password: {self.admin_password}")
        logger.info(f"🗄️ Database: {self.db_path}")
        logger.info("🛡️ Security features: IP blocking, rate limiting, input validation")
        
        try:
            # Start WebSocket server
            server = await websockets.serve(self.handle_client, self.host, self.port)
            logger.info("✅ Chat server started successfully!")
            logger.info(f"🌐 Server accessible on:")
            logger.info(f"  📍 Local: ws://localhost:{self.port}")
            logger.info(f"  📍 Network: ws://{self.host}:{self.port}")
            logger.info("🎯 Ready for connections!")
            await server.wait_closed()
        except Exception as e:
            logger.error(f"❌ Failed to start server: {e}")
            raise

def main():
    """Main entry point for secure chat server"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Secure Encrypted Chat Server - Self-Hosting")
    parser.add_argument("--host", default="0.0.0.0", help="Server host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8765, help="Server port (default: 8765)")
    parser.add_argument("--db", default="chat_data.db", help="Database file (default: chat_data.db)")
    
    args = parser.parse_args()
    
    server = PrinterMakeServer(host=args.host, port=args.port)
    server.db_path = args.db  # Allow custom database path
    
    try:
        logger.info("=" * 50)
        logger.info("🚀 SECURE CHAT SERVER STARTING")
        logger.info("=" * 50)
        asyncio.run(server.start())
    except KeyboardInterrupt:
        logger.info("🛑 Chat server stopped by user")
    except Exception as e:
        logger.error(f"❌ Server error: {e}")
        raise

if __name__ == "__main__":
    main()
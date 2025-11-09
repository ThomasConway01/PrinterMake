#!/usr/bin/env python3
"""
PrinterMake - Encryption Module
Provides secure encryption functionality for the chat system
"""

import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import secrets

class EncryptionManager:
    """Handles encryption and decryption for chat messages"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.sym_key = None
        self.fernet = None
    
    def generate_keypair(self):
        """Generate RSA key pair"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        return True
    
    def generate_symmetric_key(self):
        """Generate symmetric key for message encryption"""
        self.sym_key = Fernet.generate_key()
        self.fernet = Fernet(self.sym_key)
        return self.sym_key
    
    def encrypt_message(self, message: str) -> bytes:
        """Encrypt a message using symmetric key"""
        if not self.fernet:
            self.generate_symmetric_key()
        return self.fernet.encrypt(message.encode())
    
    def decrypt_message(self, encrypted_data: bytes) -> str:
        """Decrypt a message using symmetric key"""
        if not self.fernet:
            raise ValueError("No symmetric key available")
        return self.fernet.decrypt(encrypted_data).decode()
    
    def encrypt_symmetric_key(self, sym_key: bytes, public_key) -> bytes:
        """Encrypt symmetric key with recipient's public key"""
        return public_key.encrypt(
            sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt_symmetric_key(self, encrypted_key: bytes) -> bytes:
        """Decrypt symmetric key with private key"""
        if not self.private_key:
            raise ValueError("No private key available")
        
        return self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def export_public_key(self) -> str:
        """Export public key as base64 string"""
        if not self.public_key:
            raise ValueError("No public key available")
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_pem).decode()
    
    def import_public_key(self, public_key_b64: str):
        """Import public key from base64 string"""
        public_pem = base64.b64decode(public_key_b64.encode())
        self.public_key = serialization.load_pem_public_key(public_pem)
    
    def save_keys(self, private_path: str, public_path: str, password: str = None):
        """Save key pair to files"""
        if not self.private_key or not self.public_key:
            raise ValueError("No keys to save")
        
        # Save private key
        encryption = serialization.NoEncryption()
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
        with open(private_path, 'wb') as f:
            f.write(private_pem)
        
        # Save public key
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(public_path, 'wb') as f:
            f.write(public_pem)
    
    def load_keys(self, private_path: str, public_path: str, password: str = None) -> bool:
        """Load key pair from files"""
        try:
            # Load private key
            with open(private_path, 'rb') as f:
                private_pem = f.read()
            
            encryption = serialization.NoEncryption()
            if password:
                encryption = serialization.BestAvailableEncryption(password.encode())
            
            self.private_key = serialization.load_pem_private_key(
                private_pem,
                password=password.encode() if password else None,
                backend=None
            )
            
            # Load public key
            with open(public_path, 'rb') as f:
                public_pem = f.read()
            
            self.public_key = serialization.load_pem_public_key(public_pem)
            return True
        except Exception:
            return False
    
    def get_key_fingerprint(self) -> str:
        """Get fingerprint of the public key"""
        if not self.public_key:
            return "No key loaded"
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        fingerprint = hashlib.sha256(public_pem).hexdigest()[:16]
        return f"RSA-2048-{fingerprint}"

def generate_new_encryption_manager() -> EncryptionManager:
    """Create a new encryption manager with generated keys"""
    manager = EncryptionManager()
    manager.generate_keypair()
    return manager

def create_encryption_manager_from_keys(private_key_path: str, public_key_path: str, password: str = None) -> EncryptionManager:
    """Create encryption manager from existing keys"""
    manager = EncryptionManager()
    if manager.load_keys(private_key_path, public_key_path, password):
        return manager
    return None

# Utility functions for key derivation and password hashing
def derive_key_from_password(password: str, salt: bytes = None) -> tuple:
    """Derive encryption key from password"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def hash_password(password: str) -> str:
    """Hash password for storage"""
    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.b64encode(salt + password_hash).decode()

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    try:
        data = base64.b64decode(hashed.encode())
        salt, stored_hash = data[:16], data[16:]
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return password_hash == stored_hash
    except:
        return False
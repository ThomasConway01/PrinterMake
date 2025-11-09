#!/usr/bin/env python3
"""
Encryption Module for CLI Chat Application
Provides end-to-end encryption for secure messaging
"""

import base64
import os
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import secrets
import json

class EncryptionManager:
    """Manages encryption and decryption for secure messaging"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.key_fingerprint = None
    
    def generate_keypair(self):
        """Generate a new RSA keypair for the user"""
        try:
            # Generate private key
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Get public key
            self.public_key = self.private_key.public_key()
            
            # Generate key fingerprint
            public_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.key_fingerprint = hashlib.sha256(public_bytes).hexdigest()[:16]
            
            return True
        except Exception as e:
            print(f"Error generating keypair: {e}")
            return False
    
    def export_public_key(self) -> str:
        """Export public key as base64 string for sharing"""
        if not self.public_key:
            return None
        
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_bytes).decode('utf-8')
    
    def import_public_key(self, public_key_b64: str):
        """Import a public key from base64 string"""
        try:
            public_bytes = base64.b64decode(public_key_b64.encode('utf-8'))
            self.public_key = serialization.load_pem_public_key(public_bytes)
            return True
        except Exception as e:
            print(f"Error importing public key: {e}")
            return False
    
    def encrypt_message(self, message: str, recipient_public_key_b64: str) -> str:
        """Encrypt a message for a specific recipient using hybrid encryption"""
        try:
            # Import recipient's public key
            temp_manager = EncryptionManager()
            if not temp_manager.import_public_key(recipient_public_key_b64):
                raise ValueError("Invalid recipient public key")
            
            # Generate a random symmetric key
            symmetric_key = Fernet.generate_key()
            
            # Encrypt message with symmetric key
            fernet = Fernet(symmetric_key)
            encrypted_message = fernet.encrypt(message.encode('utf-8'))
            
            # Encrypt symmetric key with recipient's public key
            encrypted_key = temp_manager.public_key.encrypt(
                symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Combine encrypted key and encrypted message
            payload = {
                "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8'),
                "encrypted_message": base64.b64encode(encrypted_message).decode('utf-8'),
                "sender_fingerprint": self.key_fingerprint
            }
            
            return base64.b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8')
            
        except Exception as e:
            print(f"Error encrypting message: {e}")
            return None
    
    def decrypt_message(self, encrypted_payload_b64: str) -> tuple:
        """Decrypt a message received from a sender"""
        try:
            if not self.private_key:
                raise ValueError("No private key available")
            
            # Decode the payload
            payload_json = base64.b64decode(encrypted_payload_b64.encode('utf-8'))
            payload = json.loads(payload_json.decode('utf-8'))
            
            # Extract components
            encrypted_key_b64 = payload["encrypted_key"]
            encrypted_message_b64 = payload["encrypted_message"]
            sender_fingerprint = payload["sender_fingerprint"]
            
            # Decrypt symmetric key with private key
            encrypted_key = base64.b64decode(encrypted_key_b64.encode('utf-8'))
            symmetric_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt message with symmetric key
            encrypted_message = base64.b64decode(encrypted_message_b64.encode('utf-8'))
            fernet = Fernet(symmetric_key)
            decrypted_message = fernet.decrypt(encrypted_message).decode('utf-8')
            
            return decrypted_message, sender_fingerprint
            
        except Exception as e:
            print(f"Error decrypting message: {e}")
            return None, None
    
    def save_keys(self, private_key_path: str, public_key_path: str, password: str = None):
        """Save keys to files with optional password protection"""
        try:
            # Save private key
            if password:
                encryption = serialization.BestAvailableEncryption(password.encode('utf-8'))
            else:
                encryption = serialization.NoEncryption()
            
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption
            )
            
            with open(private_key_path, 'wb') as f:
                f.write(private_pem)
            
            # Save public key
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            with open(public_key_path, 'wb') as f:
                f.write(public_pem)
            
            return True
        except Exception as e:
            print(f"Error saving keys: {e}")
            return False
    
    def load_keys(self, private_key_path: str, public_key_path: str, password: str = None):
        """Load keys from files"""
        try:
            # Load private key
            with open(private_key_path, 'rb') as f:
                private_pem = f.read()
            
            if password:
                self.private_key = serialization.load_pem_private_key(
                    private_pem,
                    password=password.encode('utf-8')
                )
            else:
                self.private_key = serialization.load_pem_private_key(
                    private_pem,
                    password=None
                )
            
            # Load public key
            with open(public_key_path, 'rb') as f:
                public_pem = f.read()
            
            self.public_key = serialization.load_pem_public_key(public_pem)
            
            # Generate fingerprint
            public_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.key_fingerprint = hashlib.sha256(public_bytes).hexdigest()[:16]
            
            return True
        except Exception as e:
            print(f"Error loading keys: {e}")
            return False
    
    def get_key_fingerprint(self) -> str:
        """Get the fingerprint of the current public key"""
        return self.key_fingerprint
    
    def verify_key_integrity(self, public_key_b64: str) -> bool:
        """Verify that a public key matches its expected fingerprint"""
        try:
            if not self.import_public_key(public_key_b64):
                return False
            
            public_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            fingerprint = hashlib.sha256(public_bytes).hexdigest()[:16]
            
            return fingerprint == self.key_fingerprint
        except:
            return False

def create_encrypted_message(sender_manager: EncryptionManager, recipient_public_key_b64: str, message: str) -> str:
    """Create an encrypted message payload"""
    return sender_manager.encrypt_message(message, recipient_public_key_b64)

def decrypt_received_message(recipient_manager: EncryptionManager, encrypted_payload: str) -> tuple:
    """Decrypt a received message payload"""
    return recipient_manager.decrypt_message(encrypted_payload)

def generate_new_encryption_manager() -> EncryptionManager:
    """Generate a new EncryptionManager with fresh keypair"""
    manager = EncryptionManager()
    manager.generate_keypair()
    return manager

def main():
    """Test encryption functionality"""
    print("Testing encryption system...")
    
    # Create two users
    alice_manager = generate_new_encryption_manager()
    bob_manager = generate_new_encryption_manager()
    
    # Test message
    test_message = "Hello Bob! This is a secret message."
    
    # Alice encrypts message for Bob
    encrypted = alice_manager.encrypt_message(test_message, bob_manager.export_public_key())
    print(f"Encrypted message: {encrypted[:50]}...")
    
    # Bob decrypts message
    decrypted, sender_fingerprint = bob_manager.decrypt_message(encrypted)
    print(f"Decrypted message: {decrypted}")
    print(f"Sender fingerprint: {sender_fingerprint}")
    
    # Save keys
    alice_manager.save_keys("alice_private.pem", "alice_public.pem")
    bob_manager.save_keys("bob_private.pem", "bob_public.pem")
    
    print("Encryption test completed successfully!")

if __name__ == "__main__":
    main()
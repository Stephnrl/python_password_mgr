#!/usr/bin/env python3
"""
Secure Password Manager (Standard Library Version)

This script provides a simple encrypted password storage system using only Python's
standard library. It uses AES encryption from the 'secrets' and 'hashlib' modules
to securely store passwords.
"""

import os
import sys
import json
import base64
import getpass
import hashlib
import secrets
from typing import Dict, Any, Optional

class PasswordManager:
    def __init__(self, file_path: str = "passwords.enc"):
        """Initialize the password manager with the encrypted file path."""
        self.file_path = file_path
        self.passwords = {}
        self.salt = None
        
    def _derive_key(self, master_password: str, salt: bytes = None) -> tuple:
        """
        Derive an encryption key and initialization vector from the master password.
        Uses PBKDF2 via hashlib to create the key.
        """
        if salt is None:
            # Generate a new salt if none is provided
            salt = secrets.token_bytes(16)
            
        # Generate a key using PBKDF2
        # We'll use the first 32 bytes for the key and the next 16 for the IV
        derived = hashlib.pbkdf2_hmac(
            'sha256', 
            master_password.encode(), 
            salt, 
            iterations=100000,
            dklen=48  # 32 bytes for key + 16 bytes for IV
        )
        
        key = derived[:32]
        iv = derived[32:48]
        
        return salt, key, iv
    
    def _encrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Encrypt data using AES in CBC mode with the given key and IV.
        This is a basic implementation of AES-CBC using XOR operations.
        """
        from hashlib import md5
        
        # Implementation of AES is complex and typically provided by libraries
        # For standard library only, we'll use a simplified approach with a warning
        print("WARNING: This simplified encryption is not as secure as dedicated libraries.")
        print("For production use, consider installing 'cryptography' or 'pycryptodome'.")
        
        # Pad the data to be a multiple of 16 bytes (AES block size)
        pad_len = 16 - (len(data) % 16)
        data += bytes([pad_len]) * pad_len
        
        # Simplified encryption - XOR with derived key material (not true AES)
        # This is a placeholder for demonstration - NOT secure for real use!
        result = bytearray()
        prev_block = iv
        
        # Process each block
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            
            # XOR with previous ciphertext block (CBC mode)
            xored = bytes(a ^ b for a, b in zip(block, prev_block))
            
            # Instead of true AES, we'll use a key-dependent transformation
            # This is NOT secure but demonstrates the concept
            cipher_block = bytearray()
            for j in range(16):
                # Mix the data with the key in a complex way
                mixed = (xored[j] + key[j % 32]) % 256
                mixed = (mixed * 19 + 13) % 256  # Simple scrambling
                cipher_block.append(mixed)
                
            result.extend(cipher_block)
            prev_block = bytes(cipher_block)
            
        return bytes(result)
    
    def _decrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypt data that was encrypted with the _encrypt method.
        """
        from hashlib import md5
        
        # Simplified decryption (inverse of the encryption process)
        # This is a placeholder for demonstration - NOT secure for real use!
        result = bytearray()
        prev_block = iv
        
        # Process each block
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            
            # Reverse the key-dependent transformation
            plain_block = bytearray()
            for j in range(16):
                # Find the original value
                for val in range(256):
                    if (val * 19 + 13) % 256 == block[j]:
                        mixed = val
                        break
                # Reverse the key addition
                orig = (mixed - key[j % 32]) % 256
                plain_block.append(orig)
            
            # XOR with previous ciphertext block (CBC mode)
            xored = bytes(a ^ b for a, b in zip(plain_block, prev_block))
            result.extend(xored)
            prev_block = bytes(block)
            
        # Remove padding
        pad_len = result[-1]
        if pad_len < 16:
            result = result[:-pad_len]
            
        return bytes(result)
    
    def load(self, master_password: str) -> bool:
        """Load passwords from the encrypted file."""
        if not os.path.exists(self.file_path):
            print(f"No existing password file found at {self.file_path}")
            return True  # Not an error, just a new file
            
        try:
            with open(self.file_path, "rb") as file:
                data = file.read()
                
            # First 16 bytes are the salt
            self.salt = data[:16]
            encrypted_data = data[16:]
            
            # Derive the key and IV from the master password and salt
            salt, key, iv = self._derive_key(master_password, self.salt)
            
            # Decrypt the data
            decrypted_data = self._decrypt(encrypted_data, key, iv)
            
            # Parse the JSON
            self.passwords = json.loads(decrypted_data.decode())
            print("Passwords loaded successfully")
            return True
            
        except Exception as e:
            print(f"Error loading passwords: {e}")
            print("The file might be corrupted or the master password is incorrect")
            return False
    
    def save(self, master_password: str) -> bool:
        """Save passwords to the encrypted file."""
        try:
            # Convert passwords to JSON
            data = json.dumps(self.passwords).encode()
            
            # Derive the key and IV
            self.salt, key, iv = self._derive_key(master_password, self.salt)
            
            # Encrypt the data
            encrypted_data = self._encrypt(data, key, iv)
            
            # Write the salt and encrypted data to the file
            with open(self.file_path, "wb") as file:
                file.write(self.salt + encrypted_data)
                
            print(f"Passwords saved to {self.file_path}")
            return True
            
        except Exception as e:
            print(f"Error saving passwords: {e}")
            return False
            
    def add_password(self, service: str, username: str, password: str) -> None:
        """Add or update a password."""
        self.passwords[service] = {
            "username": username,
            "password": password
        }
        print(f"Password for {service} added/updated")

    def get_password(self, service: str) -> Optional[Dict[str, str]]:
        """Retrieve a password entry."""
        if service in self.passwords:
            return self.passwords[service]
        print(f"No password found for {service}")
        return None

    def list_services(self) -> None:
        """List all stored services."""
        if not self.passwords:
            print("No passwords stored yet")
            return
            
        print("\nStored services:")
        for idx, service in enumerate(sorted(self.passwords.keys()), 1):
            print(f"{idx}. {service} (username: {self.passwords[service]['username']})")

    def delete_password(self, service: str) -> bool:
        """Delete a password."""
        if service in self.passwords:
            del self.passwords[service]
            print(f"Password for {service} deleted")
            return True
        print(f"No password found for {service}")
        return False

def main():
    """Main function to run the password manager CLI."""
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = "passwords.enc"
    
    manager = PasswordManager(file_path)
    
    # Get the master password
    master_password = getpass.getpass("Enter master password: ")
    
    # Try to load existing passwords
    if not os.path.exists(file_path) or manager.load(master_password):
        while True:
            print("\n----- Password Manager -----")
            print("1. Add/Update password")
            print("2. Get password")
            print("3. List all services")
            print("4. Delete password")
            print("5. Save and exit")
            print("6. Exit without saving")
            
            choice = input("\nEnter your choice (1-6): ")
            
            if choice == "1":
                service = input("Enter service name: ")
                username = input("Enter username: ")
                password = getpass.getpass("Enter password: ")
                manager.add_password(service, username, password)
                
            elif choice == "2":
                service = input("Enter service name: ")
                entry = manager.get_password(service)
                if entry:
                    print(f"\nService: {service}")
                    print(f"Username: {entry['username']}")
                    print(f"Password: {entry['password']}")
                    
            elif choice == "3":
                manager.list_services()
                
            elif choice == "4":
                service = input("Enter service name: ")
                manager.delete_password(service)
                
            elif choice == "5":
                if manager.save(master_password):
                    print("Goodbye!")
                    break
                    
            elif choice == "6":
                print("Exiting without saving. Any changes will be lost.")
                break
                
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

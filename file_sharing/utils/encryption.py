import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings

def generate_key():
    """Generate a new encryption key"""
    return Fernet.generate_key().decode('utf-8')

def derive_key(password, salt=None):
    """Derive a key from a password and salt"""
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

def encrypt_file(file_path, key=None):
    """
    Encrypt a file using Fernet symmetric encryption
    
    Args:
        file_path: Path to the file to encrypt
        key: Optional encryption key (if None, a new key will be generated)
        
    Returns:
        tuple: (encrypted_file_path, encryption_key)
    """
    if key is None:
        key = generate_key()
    
    # If key is a string, convert to bytes
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    fernet = Fernet(key)
    
    # Read the file
    with open(file_path, 'rb') as file:
        file_data = file.read()
    
    # Encrypt the data
    encrypted_data = fernet.encrypt(file_data)
    
    # Write the encrypted data to a new file
    encrypted_file_path = f"{file_path}.encrypted"
    with open(encrypted_file_path, 'wb') as file:
        file.write(encrypted_data)
    
    return encrypted_file_path, key.decode('utf-8') if isinstance(key, bytes) else key

def decrypt_file(encrypted_file_path, key, output_path=None):
    """
    Decrypt a file using Fernet symmetric encryption
    
    Args:
        encrypted_file_path: Path to the encrypted file
        key: Encryption key used to encrypt the file
        output_path: Optional path to save the decrypted file (if None, a temporary path will be used)
        
    Returns:
        str: Path to the decrypted file
    """
    # If key is a string, convert to bytes
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    fernet = Fernet(key)
    
    # Read the encrypted file
    with open(encrypted_file_path, 'rb') as file:
        encrypted_data = file.read()
    
    # Decrypt the data
    decrypted_data = fernet.decrypt(encrypted_data)
    
    # Determine output path
    if output_path is None:
        output_path = os.path.join(
            settings.MEDIA_ROOT, 
            'downloads', 
            os.path.basename(encrypted_file_path).replace('.encrypted', '')
        )
    
    # Write the decrypted data to a new file
    with open(output_path, 'wb') as file:
        file.write(decrypted_data)
    
    return output_path

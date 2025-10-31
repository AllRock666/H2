# key_manager.py

import os
import sys  # Added for frozen check
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Handle bundled config path
if getattr(sys, 'frozen', False):
    CONFIG_DIR = os.path.join(sys._MEIPASS, "config")
else:
    CONFIG_DIR = "config"
PRIVATE_KEY_FILE = os.path.join(CONFIG_DIR, "private.pem")
PUBLIC_KEY_FILE = os.path.join(CONFIG_DIR, "public.pem")

def ensure_keys():
    """
    Ensures both private and public keys exist.
    Generates a new key pair if either is missing.
    """
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        return False # Keys already exist

    print("Generating new cryptographic key pair...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"Private key saved to: {PRIVATE_KEY_FILE}")

    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"Public key saved to: {PUBLIC_KEY_FILE}")
    return True

def load_private_key():
    """Loads the private key from the local config file."""
    with open(PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key():
    """Loads the public key from the local config file."""
    with open(PUBLIC_KEY_FILE, "rb") as f:
        return serialization.load_pem_public_key(f.read())
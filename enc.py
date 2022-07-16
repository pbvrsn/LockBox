import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class Cypher():
    """
    Manages encryption and decryption.
    """
    
    def __init__(self, password: bytes, salt: bytes):
        self.salt: bytes = salt
        self.password: bytes = password
        self.key: bytes = self.get_key()
        self.f = Fernet(self.key)
    
    def encrypt_text(self, text: bytes) -> bytes:
        """
        Encrypts a provided text. 
        """
        return self.f.encrypt(text)
    
    def decrypt_text(self, text: bytes) -> bytes:
        """
        Decrypts a provided text.
        """
        return self.f.decrypt(text)

    def to_bytes(self, text: str) -> bytes:
        """
        Change the type to bytes from str.
        """
        return bytes(text, "utf-8")
    
    def to_str(self, text: bytes) -> str:
        """
        Change the type to str from bytes.
        """
        return str(text, "utf-8")

    def get_key(self) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=390_000,
        )

        return base64.urlsafe_b64encode((kdf.derive(self.password)))

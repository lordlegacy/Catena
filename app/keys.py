from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def encrypt_private_key(private_pem: bytes, password: str) -> bytes:
    password_bytes = password.encode()
    return serialization.load_pem_private_key(
        private_pem,
        password=None,
        backend=default_backend()
    ).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password_bytes)
    )

def decrypt_private_key(encrypted_pem: str, password: str):
    return serialization.load_pem_private_key(
        encrypted_pem.encode(),
        password=password.encode(),
        backend=default_backend()
    )

def encrypt_message(public_key_pem: str, message: str) -> str:
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(encrypted).decode()

def decrypt_message(private_key, encrypted_message: str) -> str:
    encrypted_bytes = base64.b64decode(encrypted_message)
    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted.decode()

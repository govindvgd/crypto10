from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    return priv, pub

def save_rsa_private_key(filename, priv):
    with open(filename, "wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

def save_rsa_public_key(filename, pub):
    with open(filename, "wb") as f:
        f.write(pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_rsa_private_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_rsa_public_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_public_key(f.read())

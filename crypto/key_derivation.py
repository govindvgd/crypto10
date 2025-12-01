from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_key(shared_secret: bytes):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"crypt10-ecdh-rsa"
    )
    return hkdf.derive(shared_secret)

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def rsa_sign(private_key, data):
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def rsa_verify(public_key, data, signature):
    public_key.verify(
        signature,
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

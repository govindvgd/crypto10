import os
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

def encrypt(key, plaintext, aad=b""):
    aes = AESCCM(key)
    nonce = os.urandom(13)
    ciphertext = aes.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext

def decrypt(key, nonce, ciphertext, aad=b""):
    aes = AESCCM(key)
    return aes.decrypt(nonce, ciphertext, aad)

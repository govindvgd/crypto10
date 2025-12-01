import os
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto.rsa_keys import load_rsa_private_key, load_rsa_public_key


class SecureSession:
    def __init__(self, rsa_priv_file=None, rsa_pub_file=None):
        # Generate ephemeral ECDH key pair
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

        self.shared_key = None
        self.aesgcm = None

        self.rsa_priv_file = rsa_priv_file
        self.rsa_pub_file = rsa_pub_file

    def create_handshake_message(self):
        """
        Create ECDH public key + RSA signature for handshake.
        """
        rsa_priv = load_rsa_private_key(self.rsa_priv_file)

        pub_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        signature = rsa_priv.sign(
            pub_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return {
            "ecdsa_pub": pub_bytes.decode(),
            "signature": signature.hex()
        }

    def process_peer_handshake(self, peer_payload):
        """
        Verify peer RSA signature + derive shared AES key using ECDH.
        """
        try:
            peer_pub_bytes = peer_payload["ecdsa_pub"].encode()
            signature = bytes.fromhex(peer_payload["signature"])

            # Load peer public key (ECDH)
            peer_pub = serialization.load_pem_public_key(peer_pub_bytes)

            # Load peer RSA public key to verify signature
            rsa_pub = load_rsa_public_key(self.rsa_pub_file)
            rsa_pub.verify(
                signature,
                peer_pub_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Derive shared AES key
            shared_secret = self.private_key.exchange(ec.ECDH(), peer_pub)
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"secure-chat"
            )
            self.shared_key = hkdf.derive(shared_secret)
            self.aesgcm = AESGCM(self.shared_key)
            return True

        except Exception as e:
            print(f"[Handshake Error] {e}")
            return False

    def encrypt(self, plaintext: str):
        """
        Encrypt plaintext using AES-GCM.
        Returns (nonce, ciphertext).
        """
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode(), None)
        return nonce, ciphertext

    def decrypt(self, nonce, ciphertext):
        """
        Decrypt AES-GCM ciphertext.
        Returns plaintext string.
        """
        try:
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode()
        except Exception as e:
            print(f"[Decryption Error] {e}")
            return None

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_ecdh_keypair():
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key()
    return private, public

def serialize_ec_public(public):
    return public.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

def load_ec_public(data):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)

import json
from crypto.secure_session import SecureSession
from crypto.rsa_keys import load_rsa_private_key, load_rsa_public_key



def handle_handshake(conn, initiator=False):
    """
    Performs authenticated ECDH handshake using RSA signatures and returns a SecureSession object.
    """

    # Load RSA keys for handshake
    if initiator:
        rsa_priv = load_rsa_private_key("data/alice_priv.pem")
        peer_rsa_pub = load_rsa_public_key("data/bob_pub.pem")
    else:
        rsa_priv = load_rsa_private_key("data/bob_priv.pem")
        peer_rsa_pub = load_rsa_public_key("data/alice_pub.pem")


    # Create secure session with loaded keys
    session = SecureSession(
    rsa_priv_file="data/alice_priv.pem" if initiator else "data/bob_priv.pem",
    rsa_pub_file="data/bob_pub.pem" if initiator else "data/alice_pub.pem"
)

    try:
        if initiator:
            # Step 1: send our signed ECDH public key
            payload = session.create_handshake_message()
            conn.send(json.dumps(payload).encode())

            # Step 2: receive peer ECDH public key + signature
            data = conn.recv(4096).decode()
            peer_payload = json.loads(data)

        else:
            # Step 1: receive peer ECDH public key + signature
            data = conn.recv(4096).decode()
            peer_payload = json.loads(data)

            # Step 2: send our signed ECDH public key
            payload = session.create_handshake_message()
            conn.send(json.dumps(payload).encode())

        # Step 3: verify RSA signature + compute shared secret
        if not session.process_peer_handshake(peer_payload):
            print("[❌] Handshake authentication failed!")
            return None

        print("[🔑] Shared AES-CCM key derived successfully")
        return session

    except Exception as e:
        print(f"[ERROR Handshake] {e}")
        return None


def encrypt_and_send(message, conn, session: SecureSession):
    """
    Encrypts plaintext using AES-CCM and sends the packet containing ciphertext and nonce.
    """
    try:
        nonce, ciphertext = session.encrypt(message)
        packet = json.dumps({
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        }).encode()

        conn.send(packet)
    except Exception as e:
        print(f"[ERROR Encryption] {e}")


def receive_and_decrypt(raw_data, session: SecureSession):
    """
    Receives a packet and decrypts it using AES-CCM.
    """
    try:
        packet = json.loads(raw_data.decode())
        nonce = bytes.fromhex(packet["nonce"])
        ciphertext = bytes.fromhex(packet["ciphertext"])

        return session.decrypt(nonce, ciphertext)

    except Exception as e:
        print(f"[ERROR Decryption] {e}")
        return None

import socket
import threading
from networking.message_handler import handle_handshake, encrypt_and_send, receive_and_decrypt

HOST = "127.0.0.1"
PORT = 5000


def listen_for_messages(conn, session):
    """Background thread for receiving incoming messages."""
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                print("[⚠] Server disconnected")
                break

            message = receive_and_decrypt(data, session)
            if message:
                print(f"\nServer: {message}")
        except Exception as e:
            print(f"[ERROR Receiving] {e}")
            break


def start_client():
    """Starts the client and connects to the server."""
    print("[+] Starting Client...")
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        conn.connect((HOST, PORT))
        print(f"[+] Connected to server at {HOST}:{PORT}")
    except Exception as e:
        print(f"[ERROR] Could not connect: {e}")
        return

    # Create secure session via ECDH + RSA
    session = handle_handshake(conn, initiator=True)
    if not session:
        print("[❌] Handshake failed — exiting")
        return

    print("[🔐] Secure channel established — AES-CCM enabled")
    print("[💬] Type your message and press Enter:")

    # Background thread to listen for messages
    thread = threading.Thread(target=listen_for_messages, args=(conn, session), daemon=True)
    thread.start()

    # Loop for sending messages
    while True:
        msg = input("")
        if msg.lower() in ("exit", "quit"):
            print("[👋] Closing connection...")
            conn.close()
            break

        try:
            encrypt_and_send(msg, conn, session)
        except Exception as e:
            print(f"[ERROR Sending] {e}")
            break

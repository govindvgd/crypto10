import socket
import threading
from networking.message_handler import handle_handshake, encrypt_and_send, receive_and_decrypt


HOST = "0.0.0.0"
PORT = 5000


def handle_client(conn, addr):
    print(f"[📌] Connection received from {addr}")

    # 🔐 Step 1 — perform handshake to derive shared key
    session = handle_handshake(conn, initiator=False)
    if session is None:
        conn.close()
        return

    print("[🔐] Secure channel established. You can chat now.\n")

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            msg = receive_and_decrypt(data, session)
            if msg is None:
                continue

            print(f"Client: {msg}")
    except:
        pass
    finally:
        print("[❌] Client disconnected")
        conn.close()


def start_server():
    """
    Starts the secure chat server and waits for client connections.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)

    print(f"[🚀] Secure Chat Server Running on {HOST}:{PORT}")
    print("[⏳] Waiting for connection...")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[📢] Active connections: {threading.active_count() - 1}")

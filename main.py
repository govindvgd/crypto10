from networking.client import start_client
from networking.server import start_server
import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 main.py [server|client]")
        exit()

    mode = sys.argv[1]

    if mode == "server":
        start_server()
    elif mode == "client":
        start_client()
    else:
        print("Invalid mode! Use: server or client")

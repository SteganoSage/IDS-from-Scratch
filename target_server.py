"""
target_server.py
─────────────────
Simple TCP echo server that runs inside each IDS container.
Listens on port 9000 — gives the attack simulator something to connect to
so real TCP flows are generated and captured by the C++ capturer on eth0.

Mimics a real service (HTTP 401 responses) so flows look realistic.
"""
import socket
import threading
import os

PORT = int(os.getenv("TARGET_PORT", "9000"))


def handle(conn):
    try:
        conn.settimeout(10.0)
        while True:
            data = conn.recv(4096)
            if not data:
                break
            conn.sendall(
                b"HTTP/1.1 401 Unauthorized\r\n"
                b"Content-Length: 13\r\n"
                b"Connection: keep-alive\r\n\r\n"
                b"Unauthorized\n"
            )
    except Exception:
        pass
    finally:
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(512)
    print(f"[target_server] Listening on port {PORT}", flush=True)

    while True:
        try:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
        except Exception as e:
            print(f"[target_server] Error: {e}", flush=True)


if __name__ == "__main__":
    main()

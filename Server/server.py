import socket
import struct
import os
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "127.0.0.1"
PORT = 5000

LOG_FILE = "Server/remote_logs.log"
STATE_FILE = "Server/server_state.bin"

# Load keys

with open("Server/server_private_key.pem", "rb") as f:
    server_private_key = serialization.load_pem_private_key(
        f.read(), password=None
    )

with open("client_public_key.pem", "rb") as f:
    client_public_key = serialization.load_pem_public_key(f.read())

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed")
        data += chunk
    return data

def sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

# Load server state

if os.path.exists(STATE_FILE):
    with open(STATE_FILE, "rb") as f:
        last_hash = f.read()
else:
    last_hash = b"\x00" * 32

print("[+] Server starting with last_hash:", last_hash.hex())

# Server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)

    while True:
        print("[+] Server listening...")

        conn, addr = s.accept()
        with conn:
            print(f"[+] Connection from {addr}")

            # Receive AES key
            raw_len = recv_exact(conn, 4)
            key_len = struct.unpack(">I", raw_len)[0]
            enc_key = recv_exact(conn, key_len)

            aes_key = server_private_key.decrypt(
                enc_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            aesgcm = AESGCM(aes_key)
            print("[+] AES session established")

            # Receive logs
            while True:
                try:
                    raw_len = recv_exact(conn, 4)
                    packet_len = struct.unpack(">I", raw_len)[0]
                    packet = recv_exact(conn, packet_len)

                    nonce = packet[:12]
                    ciphertext = packet[12:]

                    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

                    # Parse
                    log_len = struct.unpack(">I", plaintext[:4])[0]
                    log_entry = plaintext[4:4 + log_len]
                    signature = plaintext[4 + log_len:]

                    # Verify signature
                    client_public_key.verify(
                        signature,
                        log_entry,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )

                    # Server-side timestamp
                    timestamp = int(time.time())

                    # Compute hash chain
                    new_hash = sha256(
                        last_hash +
                        log_entry +
                        struct.pack(">Q", timestamp)
                    )

                    # Store log 
                    with open(LOG_FILE, "ab") as f:
                        f.write(log_entry + b"\n")

                    # Update state
                    last_hash = new_hash
                    with open(STATE_FILE, "wb") as f:
                        f.write(last_hash)

                    print("[+] Log stored | hash:", last_hash.hex())

                except Exception as e:
                    print("[!] Connection closed or error:", e)
                    break

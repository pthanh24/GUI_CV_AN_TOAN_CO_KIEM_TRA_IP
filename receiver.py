import socket
from crypto_utils import *
from protocol import compute_hash, parse_full
from cryptography.hazmat.primitives import serialization

def main():
    host, port = "127.0.0.1", 12345
    whitelist = {"127.0.0.1"}
    # Nếu chạy 2 máy thì đổi thành:
    #host = "0.0.0.0" hoặc IP cụ thể của máy B.
    #whitelist = {"<IP của máy A>"}.
    priv, pub = generate_rsa_keypair()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    print(f"[Receiver] Listening on {host}:{port}...")

    conn, addr = s.accept()
    print(f"[Receiver] Connection from {addr}")

    # 1) Handshake + IP check
    hello = conn.recv(1024).decode()
    if not hello.startswith("Hello|"):
        conn.sendall(b"NACK"); return
    sender_ip = hello.split("|",1)[1]
    if sender_ip not in whitelist:
        conn.sendall(b"NACK (IP)"); return
    conn.sendall(b"Ready!")

    # 2) Gửi Receiver’s public key
    pem_recv = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.sendall(pem_recv)

    # 3) Nhận Sender’s public key
    pem_sender = b""
    while b"-----END PUBLIC KEY-----" not in pem_sender:
        pem_sender += conn.recv(1024)
    pub_sender = serialization.load_pem_public_key(pem_sender)

    # 4) Nhận gói dữ liệu duy nhất
    data = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk: break
        data += chunk

    enc_key, metadata, iv, cipher, hval, sig = parse_full(data)

    # 5) Giải khóa phiên
    session_key = rsa_decrypt(priv, enc_key)

    # 6) Kiểm toàn vẹn
    if compute_hash(iv, cipher) != hval:
        conn.sendall(b"NACK (integrity)"); print("[Receiver] integrity fail"); return

    # 7) Kiểm chữ ký với Sender’s public key
    if not verify_signature(pub_sender, sig, metadata):
        conn.sendall(b"NACK (auth)"); print("[Receiver] auth fail"); return

    # 8) Giải mã file và lưu
    plain = aes_decrypt_cbc(session_key, iv, cipher)
    with open("cv_received.pdf", "wb") as f:
        f.write(plain)

    conn.sendall(b"ACK")
    print("[Receiver] File saved as cv_received.pdf")

if __name__=="__main__":
    main()

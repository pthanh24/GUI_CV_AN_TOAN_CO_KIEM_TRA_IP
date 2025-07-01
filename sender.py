import socket, time
from crypto_utils import *
from protocol import compute_hash, package_full
from cryptography.hazmat.primitives import serialization

def main():
    host, port = "127.0.0.1", 12345
    #Nếu chạy 2 máy thì sửa thành:
    # host = "<IP của máy B>"
    # Gửi "Hello|<IP của máy A>" trong handshake.
    time.sleep(1)  # đảm bảo Receiver đã listen

    # 1) Kết nối + Handshake
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(f"Hello|{host}".encode())
    if s.recv(1024) != b"Ready!":
        print("Refused"); return

    # 2) Nhận Receiver’s public key
    pem_recv = b""
    while b"-----END PUBLIC KEY-----" not in pem_recv:
        pem_recv += s.recv(1024)
    pub_recv = serialization.load_pem_public_key(pem_recv)

    # 3) Gửi Sender’s public key
    priv_s, pub_s = generate_rsa_keypair()
    pem_sender = pub_s.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    s.sendall(pem_sender)

    # 4) Chuẩn bị metadata + ký
    filename, ts = "cv.pdf", str(time.time())
    metadata = f"{filename}|{ts}|{host}".encode()
    sig = sign_data(priv_s, metadata)

    # 5) AES encrypt
    session_key = generate_aes_key()
    iv = os.urandom(16)
    with open("cv.pdf","rb") as f: plain = f.read()
    cipher = aes_encrypt_cbc(session_key, iv, plain)
    hval = compute_hash(iv, cipher)

    # 6) RSA encrypt session key
    enc_key = rsa_encrypt(pub_recv, session_key)

    # 7) Gói & gửi 1 lần
    packet = package_full(enc_key, metadata, iv, cipher, hval, sig)
    s.sendall(packet)
    s.shutdown(socket.SHUT_WR)

    # 8) Chờ ACK
    resp = s.recv(1024)
    print("[Sender] Response:", resp.decode())

if __name__=="__main__":
    main()

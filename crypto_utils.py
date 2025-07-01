from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    return private_key, private_key.public_key()

def rsa_encrypt(public_key, data):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def sign_data(private_key, data):
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA512()
    )

def verify_signature(public_key, signature, data):
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA512())
        return True
    except:
        return False

def generate_aes_key():
    return os.urandom(32)

def aes_encrypt_cbc(key, iv, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    pad = 16 - len(plaintext) % 16
    plaintext += bytes([pad]) * pad
    return encryptor.update(plaintext) + encryptor.finalize()

def aes_decrypt_cbc(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    data = decryptor.update(ciphertext) + decryptor.finalize()
    pad = data[-1]
    return data[:-pad]

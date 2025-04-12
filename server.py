import socketserver
import os
import json

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def encrypt_message(public_key, message):
    """
    Encrypt a message using the recipient's public key.
    Args:
        public_key: The recipient's public RSA key.
        message: The plaintext message to encrypt (bytes).
    Returns:
        The encrypted message (bytes).
    """
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_message(private_key, ciphertext):
    """
    Decrypt a message using the recipient's private key.
    Args:
        private_key: The recipient's private RSA key.
        ciphertext: The encrypted message to decrypt (bytes).
    Returns:
        The decrypted message (bytes).
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        print(f"Connection established with {self.client_address[0]}:{self.client_address[1]}")
        
        # receive the public key from the client
        client_public = self.request.recv(4096)
        client_public = serialization.load_pem_public_key(client_public)
        
        # send client server public key
        self.request.sendall(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        # receive the encrypted message from the client
        self.data = self.request.recv(4096)
        
        self.data = json.loads(self.data.decode())
        if self.data["command"] == "register":
            self.data["payload"]["username"] = decrypt_message(private_key, bytes.fromhex(self.data["payload"]["username"]))
        print(f"Received message: {self.data}")




class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

def generate_keys(key_size):
    """Generate a new RSA key pair."""
    if not os.path.exists("private_key.pem"):
        with open("private_key.pem", "wb") as priv_file:
            private_key = rsa.generate_private_key(
                public_exponent=65537,  
                key_size=key_size,
            )
            priv_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    with open("private_key.pem", "rb") as priv_file:
        private_key = serialization.load_pem_private_key(
            priv_file.read(),
            password=None,
        )
    if not os.path.exists("public_key.pem"):
        public_key = private_key.public_key()
        with open("public_key.pem", "wb") as pub_file:
            pub_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    with open("public_key.pem", "rb") as pub_file:
        public_key = serialization.load_pem_public_key(
            pub_file.read(),
        )
    return private_key, public_key

if __name__ == "__main__":
    HOST, PORT = "192.168.0.4", 9999
    KEY_SIZE = 2048

    private_key, public_key = generate_keys(KEY_SIZE)
    with ThreadedTCPServer((HOST, PORT), MyTCPHandler) as server:
        print(f"Serving on {HOST}:{PORT}")
        server.serve_forever()


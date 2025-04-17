import random
import socketserver
import os
import json
from datetime import datetime
import sqlite3

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

def send_message(sock, command, payload):
    sock.sendall(json.dumps({
        "timestamp": datetime.now().isoformat(),
        "command": command,
        "payload": payload
    }).encode())

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
        while True:
            self.data = self.request.recv(4096)
            self.data = json.loads(self.data.decode())
            print(f"Received message: {self.data}")
            match self.data["command"]:
                case "register":
                    con = sqlite3.connect('database.db')
                    cursor = con.cursor()
                    cursor.execute("SELECT name FROM users")
                    hosts = [host[0] for host in cursor.fetchall()]

                    self.data["payload"]["username"] = decrypt_message(private_key, bytes.fromhex(self.data["payload"]["username"])).decode()
                    #host = hosts.find_one({"username":self.data["payload"]["username"]})
                    print(hosts)
                    if self.data["payload"]["username"] in hosts:
                        send_message(self.request, "register", {
                            "status": "fail",
                            "message": "Username already exists"
                        })
                        con.close()
                        break
                    else:
                        #hosts.insert_one({"username":self.data["payload"]["username"], "public_key": client_public.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)})
                        cursor.execute("INSERT INTO users (name, pub) VALUES (?, ?)", (self.data["payload"]["username"], client_public.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)))
                        
                        send_message(self.request, "register", {
                            "status": "success",
                            "message": "User registered successfully"
                        })
                        print(f"User {self.data['payload']['username']} registered successfully")
                    con.commit()
                    con.close()
                case "login":
                    con = sqlite3.connect('database.db')
                    cursor = con.cursor()
                    cursor.execute("SELECT name FROM users")
                    hosts = [host[0] for host in cursor.fetchall()]

                    self.data["payload"]["username"] = decrypt_message(private_key, bytes.fromhex(self.data["payload"]["username"])).decode()
                    #host = hosts.find_one({"username":self.data["payload"]["username"]})
                    print(hosts)
                    print(self.data["payload"]["username"])
                    if self.data["payload"]["username"] not in hosts:
                        send_message(self.request, "login", {
                            "status": "fail",
                            "message": "Username does not exist"
                        })
                        con.close()
                        break
                    else:
                        if self.data["payload"]["username"] in connected:
                            send_message(self.request, "login", {       
                                "status": "fail",
                                "message": "User already logged in"
                            })
                            con.close()
                            break
                        # Generate a random token for the user
                        token = int(datetime.now().timestamp()) + random.randint(0, 1000000)
                        connected[self.data["payload"]["username"]] = [self.request, token]
                        send_message(self.request, "login", {
                            "status": "success",
                            "message": "User logged in successfully",
                            "token-sig": encrypt_message(client_public, str(token).encode()).hex(),
                        })
                        con.close()
                        print(f"User {self.data['payload']['username']} logged in with token {token}")
                case "login-verif":
                    self.data["payload"]["username"] = decrypt_message(private_key, bytes.fromhex(self.data["payload"]["username"])).decode()
                    if self.data["payload"]["username"] not in connected:
                        send_message(self.request, "login-verif", {
                            "status": "fail",
                            "message": "User not logged in"
                        })
                        break
                    else:
                        token = decrypt_message(private_key, bytes.fromhex(self.data["payload"]["token-sig"]))
                        if token == str(connected[self.data["payload"]["username"]][1]).encode():
                            send_message(self.request, "login-verif", {
                                "status": "success",
                                "message": "User verified successfully"
                            })
                            print(f"User {self.data['payload']['username']} verified successfully")
                        else:
                            send_message(self.request, "login-verif", {
                                "status": "fail",
                                "message": "Token verification failed"
                            })
                            break
                case "online-list":
                    send_message(self.request, "online-list", {
                        "status": "success",
                        "users": list(connected.keys())
                    })
                    print(f"Online users: {list(connected.keys())}")
                case "message":
                    if self.data["payload"]["from"] not in connected:
                        send_message(self.request, "message", {
                            "status": "fail",
                            "message": "User not logged in"
                        })
                        break
                    """
                    messages.insert_one({
                            "from": self.data["payload"]["from"],
                            "to": self.data["payload"]["to"],
                            "aes": self.data["payload"]["aes"],
                            "msg-cont": self.data["payload"]["msg-cont"],
                            "timestamp": datetime.now().isoformat(timespec="seconds"),
                    })
                    """
                    con = sqlite3.connect('database.db')
                    cursor = con.cursor()
                    cursor.execute("SELECT name FROM users")
                    hosts = [host[0] for host in cursor.fetchall()]

                    for receipient in self.data["payload"]["to"]:
                        if receipient not in hosts:
                            send_message(self.request, "message", {
                                "status": "fail",
                                "message": f"Recipient {receipient} does not exist"
                            })
                            con.close()
                            break
                        if receipient in connected:
                            send_message(connected[receipient][0], "message", {
                                "from": self.data["payload"]["from"],
                                "to": receipient,
                                "aes": self.data["payload"]["aes"],
                                "msg-cont": self.data["payload"]["msg-cont"],
                            })
                            print(f"Retransmited message from {self.data['payload']['from']} to {self.data['payload']['to']}")

                    cursor.execute("""INSERT INTO messages VALUES (NULL, ?, ?, ?)""", (
                        self.data["sender_timestamp"],
                        str(self.data["payload"]["to"]),
                        str(self.data["payload"])
                    ))
                    con.commit()
                    con.close()
                case "sync":
                    key = next((key for key, value in connected.items() if value[0] == self.request), None)

                    if key is None:
                        send_message(self.request, "sync", {
                            "status": "fail",
                            "message": "User not registered"
                        })
                        break
                    
                    con = sqlite3.connect('database.db')
                    cursor = con.cursor()
                    cursor.execute("SELECT payload FROM messages WHERE sender_timestamp BETWEEN ? AND ? AND receivers LIKE ?", (self.data["payload"]["from"], self.data["payload"]["to"], f"%{key}%"))
                    msgs = [msgs[0] for msgs in cursor.fetchall()]
                    
                    send_message(self.request, "sync", {
                        "status": "success",
                        "payload": msgs
                    })
                    con.close()

                case "logout":
                    key = next((key for key, value in connected.items() if value[0] == self.request), None)
                    if key is None:
                        send_message(self.request, "logout", {
                            "status": "fail",
                            "message": "User not logged in"
                        })
                        return
                    else:
                        del connected[key]
                        send_message(self.request, "logout", {
                            "status": "success",
                            "message": "User logged out successfully"
                        })
                        print(f"User {key} logged out successfully")
                        return

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

def create_tables():
    con = sqlite3.connect('database.db')
    cursor = con.cursor()
    table = """ CREATE TABLE IF NOT EXISTS users (
                name VARCHAR(255) PRIMARY KEY,
                pub VARCHAR(255) NOT NULL
    ); """
    cursor.execute(table)
    table = """ CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_timestamp VARCHAR(255) NOT NULL,
                receivers VARCHAR(255) NOT NULL,
                payload VARCHAR(255) NOT NULL
    ); """
    cursor.execute(table)
    con.commit()
    con.close()

if __name__ == "__main__":
    HOST, PORT = "192.168.0.4", 9999
    HOST = input("Enter the server address: ")
    PORT = int(input("Enter the server port: "))
    KEY_SIZE = 2048
    
    create_tables()
    connected = {}

    private_key, public_key = generate_keys(KEY_SIZE)
    with ThreadedTCPServer((HOST, PORT), MyTCPHandler) as server:
        print(f"Serving on {HOST}:{PORT}")
        server.serve_forever()
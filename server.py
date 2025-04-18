import time
import socket
import threading
import sys
import json
import datetime
import sqlite3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

NULL_TOKEN = 0

# only for err/ack responses
def gen_response(rtype, message):
    if rtype != "error" and rtype != "ack":
        raise ValueError("Wrong type passed for response generation")

    timestamp = datetime.datetime.now().isoformat()

    response = {
        "timestamp": timestamp, 
        "type": rtype, 
        "response": {
            "message": message
        }
    }
    return json.dumps(response)

def create_tables():
    connection_obj = sqlite3.connect('database.db')
    cursor_obj = connection_obj.cursor()
    table = """ CREATE TABLE IF NOT EXISTS users (
                name VARCHAR(255) PRIMARY KEY,
                pub VARCHAR(255) NOT NULL
    ); """
    cursor_obj.execute(table)
    table = """ CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_timestamp VARCHAR(255) NOT NULL,
                command VARCHAR(255) NOT NULL,
                payload VARCHAR(255) NOT NULL
    ); """
    cursor_obj.execute(table)
    connection_obj.commit()
    connection_obj.close()


def command_register(sender, payload):
    connection_obj = sqlite3.connect('database.db')
    cursor_obj = connection_obj.cursor()
    cursor_obj.execute("SELECT * FROM users")
    user_list = cursor_obj.fetchall()

    for user_info in user_list:
        user = user_info[0]
        if user == payload['name']:
            sender.send(gen_response('error', 'username already exists').encode())
            connection_obj.close()
            return

    cursor_obj.execute("INSERT INTO users (name, pub) VALUES (?, ?)", (payload['name'], payload['pub']))
    connection_obj.commit()
    connection_obj.close()
    sender.send(gen_response('ack', 'registered succesfully').encode())
    return


def command_login(sender, payload, existence_checked, given_token):
    if not existence_checked:
        connection_obj = sqlite3.connect('database.db')
        cursor_obj = connection_obj.cursor()
        cursor_obj.execute("""SELECT * FROM users""")
        user_list = cursor_obj.fetchall()
        connection_obj.close()

        user_exists = False
        for user_info in user_list:
            if user_info[0] == payload['name']:
                user_exists = True
                key = user_info[1]
                break

        if not user_exists:
            sender.send(gen_response('error', 'user does not exist').encode())
            return NULL_TOKEN

        token = hex(int(time.time()))
        cipher = PKCS1_OAEP.new(RSA.import_key(key))
        ciphertext = cipher.encrypt(bytes(token, 'utf-8'))
        sender.send(ciphertext)
        return token

    received_token = payload['token-sig']
    if received_token == given_token:
        for user in active_users:
            if user['name'] == payload['name'] and user['socket'] == sender:
                sender.send(gen_response('error', 'user is already logged in').encode())
                return NULL_TOKEN
        sender.send(gen_response('ack', 'logged in succesfully').encode())
        active_users.append({
            'name': payload['name'],
            'token': received_token,
            'socket': sender
        })
    else:
        sender.send(gen_response('error', 'invalid login data (your priv key is probably wrong)').encode())
    return NULL_TOKEN


def command_logout(sender, payload):
    for user in active_users:
        if payload['name'] == user['name']:
            active_users.remove(user)
            sender.send(gen_response('ack', 'logged out succesfully').encode())
            return
    sender.send(gen_response('error', 'you are not logged in').encode())
    return


def command_online_list(sender):
    active_users_list = {
      "timestamp": datetime.datetime.now().isoformat(),
      "type": "online-list",
      "response": {
        "users": []
      }
    }

    connection_obj = sqlite3.connect('database.db')
    cursor_obj = connection_obj.cursor()

    for user in active_users:
        username = user['name']
        cursor_obj.execute("SELECT pub FROM users WHERE name = ?;", (username,))
        temp_pub = cursor_obj.fetchone()[0] 
        active_users_list['response']['users'].append({'name': username, 'pub': temp_pub})

    connection_obj.close()

    print(active_users)
    sender.send(json.dumps(active_users_list).encode())

    return


def command_send(sender, message):
    payload = message['payload']
    sender_online = False
    for user in active_users:
        if payload['sender'] == user['name']:
            sender_online = True
    if not sender_online:
        sender.send(gen_response('error', 'you are not logged in').encode())
        return

    connection_obj = sqlite3.connect('database.db')
    cursor_obj = connection_obj.cursor()
    cursor_obj.execute("""SELECT * FROM users""")
    user_list = cursor_obj.fetchall()

    if not payload['key_known']:
        user_exists = False
        for user in user_list:
            if user[0] == payload['receiver']:
                user_exists = True
                sender.send(user[1].encode('utf-8'))
                return

        if not user_exists:
            sender.send(gen_response('error', 'receiver does not exist').encode())
            connection_obj.close()
            return

    payload.pop('key_known')
    for user in active_users:
        if user['name'] == payload['receiver']:
            user['socket'].send(str(message).encode('utf-8'))

    cursor_obj.execute("""INSERT INTO messages VALUES (NULL, ?, ?, ?)""", (
        message['sender_timestamp'],
        message['command'],
        str(payload)
    ))
    connection_obj.commit()
    connection_obj.close()
    return


def command_sync(sender, payload):
    sender_online = False
    for user in active_users:
        if payload['name'] == user['name']:
            sender_online = True
    if not sender_online:
        sender.send(gen_response('error', 'you are not logged in').encode())
        return

    connection_obj = sqlite3.connect('database.db')
    cursor_obj = connection_obj.cursor()
    cursor_obj.execute("SELECT * FROM messages WHERE sender_timestamp BETWEEN ? AND ?", (payload['from'], payload['to']))
    message_list = cursor_obj.fetchall()
    connection_obj.close()

    for message in message_list:
        message_payload = eval(message[3])
        if message_payload['receiver'] != payload['name']:
            message_list.pop(message_list.index(message))
            continue
        sender.send(str(message).encode('utf-8'))
    return


def connection_handler(client, addr):
    print('[!] Połączenie odebrane. Adres klienta: {0}:{1}'.format(addr[0], addr[1]))
    while True:
        msg = client.recv(1024).decode('utf-8')
        command = json.loads(msg)['command']
        print(json.loads(msg))
        match command:
            case 'register':
                command_register(client, json.loads(msg)['payload'])
            case 'login':
                temp_token = command_login(client, json.loads(msg)['payload'], False, NULL_TOKEN)
            case 'login-verif':
                command_login(client, json.loads(msg)['payload'], True, temp_token)
            case 'logout':
                command_logout(client, json.loads(msg)['payload'])
            case 'online_list':
                command_online_list(client)
            case 'message':
                command_send(client, json.loads(msg))
            case 'sync':
                command_sync(client, json.loads(msg)['payload'])
            case 'quit':
                client.close()
                exit(0)


if __name__ == "__main__":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if len(sys.argv) != 3:
        server.bind(('localhost', 6969))
    else:
        server.bind((sys.argv[1], int(sys.argv[2])))
    active_users = []
    create_tables()
    server.listen(100)

    print('[!] Rozpoczynam słuchanie.')
    while True:
        client, addr = server.accept()
        threading.Thread(target=connection_handler, args=(client, addr)).start()

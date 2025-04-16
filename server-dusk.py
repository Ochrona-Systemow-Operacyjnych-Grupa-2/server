import time
import socket
import threading
import sys
import json
import sqlite3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

NULL_TOKEN = 0


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
            sender.send('Nazwa użytkownika zajęta.'.encode('utf-8'))
            connection_obj.close()
            return

    cursor_obj.execute("INSERT INTO users (name, pub) VALUES (?, ?)", (payload['name'], payload['pub']))
    connection_obj.commit()
    connection_obj.close()
    sender.send('Zarejestrowano pomyślnie.'.encode('utf-8'))
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
            sender.send('Użytkownik nie istnieje.'.encode('utf-8'))
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
                sender.send("Użytkownik jest już zalogowany.".encode('utf-8'))
                return NULL_TOKEN
        sender.send('Zalogowano pomyślnie.'.encode('utf-8'))
        active_users.append({
            'name': payload['name'],
            'token': received_token,
            'socket': sender
        })
    else:
        sender.send('Nieprawidłowe dane logowania (prawdopodobnie posiadasz zły klucz prywatny).'.encode('utf-8'))
    return NULL_TOKEN


def command_logout(sender, payload):
    for user in active_users:
        if payload['name'] == user['name']:
            active_users.remove(user)
            sender.send('Pomyślnie wylogowano Cię z sesji.'.encode('utf-8'))
            return
    sender.send('Użytkownik nie jest zalogowany.'.encode('utf-8'))
    return


def command_online_list(sender):
    sender.send(str(active_users).encode('utf-8'))
    return


def command_send(sender, message):
    payload = message['payload']
    sender_online = False
    for user in active_users:
        if payload['sender'] == user['name']:
            sender_online = True
    if not sender_online:
        sender.send('Nie jesteś zalogowany.'.encode('utf-8'))
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
            sender.send('Odbiorca nie istnieje.'.encode('utf-8'))
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
        sender.send('Nie jesteś zalogowany.'.encode('utf-8'))
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
        print(command)
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
            case 'send':
                command_send(client, json.loads(msg))
            case 'sync':
                command_sync(client, json.loads(msg)['payload'])
            case 'quit':
                client.close()
                exit(0)


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

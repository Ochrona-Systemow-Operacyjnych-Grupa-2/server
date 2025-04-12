# server
chat app's server
for more info visit [this](https://github.com/Ochrona-Systemow-Operacyjnych-Grupa-2/notatka).

## Jak to działa 
```
Client PUB -> Server
Client <- Server PUB 
```
Potem Client wysyła comendy, i server dostaje coś takiego, ale pole payload jest zaszyfrowane kluczem publicznym servera. 
```
Received message: {'timestamp': '2025-04-12T22:09:28.981173', 'command': 'register', 'payload': {'username': b'Katameqqe'}}
```
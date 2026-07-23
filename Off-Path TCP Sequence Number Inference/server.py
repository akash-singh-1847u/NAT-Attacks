import socket

HOST = "20.0.0.20"
PORT = 8080

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind((HOST, PORT))
server.listen(5)

print("Listening...")

while True:

    client, addr = server.accept()

    print("=" * 40)
    print("Client:", addr)

    while True:

        data = client.recv(1024)

        if not data:
            break

        print("Received:", data.decode())

        client.send(b"Hello client")

    client.close()
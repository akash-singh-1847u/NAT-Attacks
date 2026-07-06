import socket

HOST = "0.0.0.0"
PORT = 8080

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)

print("=" * 50)
print("Server Listening on Port 8080")
print("=" * 50)

while True:
    conn, addr = server.accept()

    print("\n" + "=" * 50)
    print("Client Connected!")
    print(f"Client IP   : {addr[0]}")
    print(f"Client Port : {addr[1]}")

    while True:
        data = conn.recv(1024)

        if not data:
            print("Client Disconnected")
            break

        print(f"Received Data : {data.decode()}")

        conn.send(b"Hello Client")

    conn.close()
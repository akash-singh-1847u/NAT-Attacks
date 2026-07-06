import socket

SERVER = "20.0.0.20"
PORT = 8080

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((SERVER, PORT))

client.send(b"Hello from Client")

reply = client.recv(1024)

print("Server Reply:", reply.decode())

client.close()
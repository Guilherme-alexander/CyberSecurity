"""
[CLIENT]

Socket Programming in Python

>python client.py
Connected to server at 127.0.0.1:8080
Sent: Client is sending greetings!
Server response: Server's message

"""

import socket
import sys

PORT = 8080
SERVER_IP = "127.0.0.1"

def main():
    try:
        # Criar socket
        cli_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Conectar ao servidor
        ser_address = (SERVER_IP, PORT)
        cli_socket.connect(ser_address)
        print(f"Connected to server at {SERVER_IP}:{PORT}")
        
        # Enviar mensagem
        message = "Client is sending greetings!"
        cli_socket.send(message.encode('utf-8'))
        print(f"Sent: {message}")
        
        # Receber resposta
        buf = cli_socket.recv(1024).decode('utf-8')
        print(f"Server response: {buf}")
        
        # Fechar conexão
        cli_socket.close()
        
    except socket.error as e:
        print(f"Socket error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

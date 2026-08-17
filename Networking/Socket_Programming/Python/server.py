"""
[SERVER]

Socket Programming in Python

>python server.py
Server listening on port 8080...
Client connected from 127.0.0.1:40694
Client's message is: Client is sending greetings!

"""

import socket
import sys

PORT = 8080
MAX_BUF_SIZE = 1024

def main():
    try:
        # Criar socket
        ser_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Permitir reutilização da porta (útil para reinícios rápidos)
        ser_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind
        ser_address = ('0.0.0.0', PORT)
        ser_socket.bind(ser_address)
        
        # Listen
        ser_socket.listen(3)
        print(f"Server listening on port {PORT}...")
        
        # Aceitar conexão
        cli_socket, cli_address = ser_socket.accept()
        print(f"Client connected from {cli_address[0]}:{cli_address[1]}")
        
        # Receber mensagem do cliente
        buf = cli_socket.recv(MAX_BUF_SIZE).decode('utf-8')
        print(f"Client's message is: {buf}")
        
        # Enviar resposta
        response = "Server's message"
        cli_socket.send(response.encode('utf-8'))
        
        # Fechar conexões
        cli_socket.close()
        ser_socket.close()
        
    except socket.error as e:
        print(f"Socket error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

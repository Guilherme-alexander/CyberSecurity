/*
File: client.c

>client
Connected to server at 127.0.0.1:8080
Sent: Client is sending greetings!
Server response: Server's message

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <sys/types.h>
#endif

#define PORT 8080
#define SERVER_IP "127.0.0.1"

#ifdef _WIN32
    #define SOCKET_TYPE SOCKET
    #define INVALID_SOCKET_VAL INVALID_SOCKET
    #define SOCKET_ERROR_VAL SOCKET_ERROR
    #define CLOSE_SOCKET(s) closesocket(s)
#else
    #define SOCKET_TYPE int
    #define INVALID_SOCKET_VAL -1
    #define SOCKET_ERROR_VAL -1
    #define CLOSE_SOCKET(s) close(s)
#endif

int main() {
    SOCKET_TYPE cli_socket;
    struct sockaddr_in ser_address;
    char buf[1024] = {0};
    const char* message = "Client is sending greetings!";
    
    #ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            printf("WSAStartup failed\n");
            return 1;
        }
    #endif
    
    // Criar socket
    if ((cli_socket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET_VAL) {
        #ifdef _WIN32
            printf("Error in socket creation: %d\n", WSAGetLastError());
            WSACleanup();
        #else
            perror("Error in socket creation");
        #endif
        exit(EXIT_FAILURE);
    }
    
    // Configurar endereço do servidor
    ser_address.sin_family = AF_INET;
    ser_address.sin_port = htons(PORT);
    
    // Converter IP
    if (inet_pton(AF_INET, SERVER_IP, &ser_address.sin_addr) <= 0) {
        #ifdef _WIN32
            printf("Wrong address format\n");
        #else
            perror("Wrong address format");
        #endif
        CLOSE_SOCKET(cli_socket);
        #ifdef _WIN32
            WSACleanup();
        #endif
        exit(EXIT_FAILURE);
    }
    
    // Conectar ao servidor
    if (connect(cli_socket, (struct sockaddr*)&ser_address, sizeof(ser_address)) == SOCKET_ERROR_VAL) {
        #ifdef _WIN32
            printf("Connection failure: %d\n", WSAGetLastError());
            CLOSE_SOCKET(cli_socket);
            WSACleanup();
        #else
            perror("Connection failure");
            CLOSE_SOCKET(cli_socket);
        #endif
        exit(EXIT_FAILURE);
    }
    
    printf("Connected to server at %s:%d\n", SERVER_IP, PORT);
    
    // Enviar mensagem
    if (send(cli_socket, message, strlen(message), 0) == SOCKET_ERROR_VAL) {
        #ifdef _WIN32
            printf("Send failed: %d\n", WSAGetLastError());
        #else
            perror("Send failed");
        #endif
        CLOSE_SOCKET(cli_socket);
        #ifdef _WIN32
            WSACleanup();
        #endif
        exit(EXIT_FAILURE);
    }
    
    printf("Sent: %s\n", message);
    
    // Receber resposta
    int bytes_received = recv(cli_socket, buf, sizeof(buf) - 1, 0);
    if (bytes_received > 0) {
        buf[bytes_received] = '\0';
        printf("Server response: %s\n", buf);
    } else {
        #ifdef _WIN32
            printf("Receive failed or server closed connection: %d\n", WSAGetLastError());
        #else
            perror("Receive failed or server closed connection");
        #endif
    }
    
    // Fechar conexão
    CLOSE_SOCKET(cli_socket);
    
    #ifdef _WIN32
        WSACleanup();
    #endif
    
    return 0;
}

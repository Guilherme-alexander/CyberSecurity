/*
File: server.c

>server
Server listening on port 8080...
Client connected from 127.0.0.1:3651
Client's message is: Client is sending greetings!
Sent response: Server's message

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
#define MAX_BUF_SIZE 1024

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
    SOCKET_TYPE ser_socket, cli_socket;
    struct sockaddr_in ser_address, cli_address;
    char buf[MAX_BUF_SIZE] = {0};
    int cli_address_len = sizeof(cli_address);
    
    #ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            printf("WSAStartup failed\n");
            return 1;
        }
    #endif
    
    // Criar socket
    if ((ser_socket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET_VAL) {
        #ifdef _WIN32
            printf("Error in Socket creation: %d\n", WSAGetLastError());
            WSACleanup();
        #else
            perror("Error in Socket creation");
        #endif
        exit(EXIT_FAILURE);
    }
    
    #ifndef _WIN32
        // Permitir reutilização da porta no Linux
        int opt = 1;
        if (setsockopt(ser_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            perror("setsockopt failed");
            CLOSE_SOCKET(ser_socket);
            exit(EXIT_FAILURE);
        }
    #endif
    
    // Configurar endereço
    ser_address.sin_family = AF_INET;
    ser_address.sin_addr.s_addr = INADDR_ANY;
    ser_address.sin_port = htons(PORT);
    
    // Bind
    if (bind(ser_socket, (struct sockaddr*)&ser_address, sizeof(ser_address)) == SOCKET_ERROR_VAL) {
        #ifdef _WIN32
            printf("Failure in bind: %d\n", WSAGetLastError());
            CLOSE_SOCKET(ser_socket);
            WSACleanup();
        #else
            perror("Failure in bind");
            CLOSE_SOCKET(ser_socket);
        #endif
        exit(EXIT_FAILURE);
    }
    
    // Listen
    if (listen(ser_socket, 3) == SOCKET_ERROR_VAL) {
        #ifdef _WIN32
            printf("Failed to Listen: %d\n", WSAGetLastError());
            CLOSE_SOCKET(ser_socket);
            WSACleanup();
        #else
            perror("Failed to Listen");
            CLOSE_SOCKET(ser_socket);
        #endif
        exit(EXIT_FAILURE);
    }
    
    printf("Server listening on port %d...\n", PORT);
    
    // Aceitar conexão
    if ((cli_socket = accept(ser_socket, (struct sockaddr*)&cli_address, &cli_address_len)) == INVALID_SOCKET_VAL) {
        #ifdef _WIN32
            printf("Failed to accept: %d\n", WSAGetLastError());
            CLOSE_SOCKET(ser_socket);
            WSACleanup();
        #else
            perror("Failed to accept");
            CLOSE_SOCKET(ser_socket);
        #endif
        exit(EXIT_FAILURE);
    }
    
    printf("Client connected from %s:%d\n", 
           inet_ntoa(cli_address.sin_addr), 
           ntohs(cli_address.sin_port));
    
    // Receber mensagem do cliente
    int bytes_received = recv(cli_socket, buf, MAX_BUF_SIZE - 1, 0);
    if (bytes_received > 0) {
        buf[bytes_received] = '\0';
        printf("Client's message is: %s\n", buf);
    }
    
    // Enviar resposta
    const char* response = "Server's message";
    send(cli_socket, response, strlen(response), 0);
    
    printf("Sent response: %s\n", response);
    
    // Fechar conexões
    CLOSE_SOCKET(cli_socket);
    CLOSE_SOCKET(ser_socket);
    
    #ifdef _WIN32
        WSACleanup();
    #endif
    
    return 0;
}

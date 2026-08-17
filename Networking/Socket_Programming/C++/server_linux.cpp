/*
BLOG: https://linuxhint.com/socket-programming-cpp

[BUILD MinGW g++]
g++ -o server server_linux.cpp

[Use]
./server
Server listening on port 8080...
Client's message is: Client is sending greetings! --> [connect message to client]

*/
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

using namespace std;

#define PORT 8080
#define MAX_BUF_SIZE 1024

int main() {
    int ser_socket, cli_socket;
    struct sockaddr_in ser_address, cli_address;
    char buf[MAX_BUF_SIZE] = {0};

    if ((ser_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Error in the Socket creation");
        exit(EXIT_FAILURE);
    }

    ser_address.sin_family = AF_INET;
    ser_address.sin_addr.s_addr = INADDR_ANY;
    ser_address.sin_port = htons(PORT);

    if (bind(ser_socket, (struct sockaddr*)&ser_address, sizeof(ser_address)) == -1) {
        perror("Failure in bind");
        exit(EXIT_FAILURE);
    }

    if (listen(ser_socket, 3) == -1) {
        perror("Failed to Listen");
        exit(EXIT_FAILURE);
    }

    cout << "Server listening on port " << PORT << "...\n";

    socklen_t cli_address_len = sizeof(cli_address);
    if ((cli_socket = accept(ser_socket, (struct sockaddr*)&cli_address, &cli_address_len)) == -1) {
        perror("Failed to accept");
        exit(EXIT_FAILURE);
    }

    read(cli_socket, buf, MAX_BUF_SIZE);
    cout << "Client's message is: " << buf <<endl;

    send(cli_socket, "Server's message", strlen("Server's message"), 0);

    close(cli_socket);
    close(ser_socket);

    return 0;
}

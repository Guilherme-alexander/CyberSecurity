/*
BLOG: https://linuxhint.com/socket-programming-cpp

[BUILD MinGW g++]
g++ -o client client_linux.cpp

[Use]
./client
Server response: Server's message --> send messagem

*/
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define SERVER_IP "127.0.0.1"

int main() {
    int cli_socket;
    struct sockaddr_in ser_address;
    const char* mesg = "Client is sending greetings!";

    if ((cli_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Error in socket creation");
        exit(EXIT_FAILURE);
    }

    ser_address.sin_family = AF_INET;
    ser_address.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &ser_address.sin_addr) <= 0) {
        perror("Wrong address");
        exit(EXIT_FAILURE);
    }

    if (connect(cli_socket, (struct sockaddr*)&ser_address, sizeof(ser_address)) == -1) {
        perror("Connection failure");
        exit(EXIT_FAILURE);
    }
    send(cli_socket, mesg, strlen(mesg), 0);

    char buf[1024] = {0};
    read(cli_socket, buf, sizeof(buf));
    std::cout << "Server response: " << buf << std::endl;

    close(cli_socket);
    return 0;
}

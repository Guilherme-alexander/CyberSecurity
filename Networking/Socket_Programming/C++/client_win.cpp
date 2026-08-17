#include <iostream>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080
#define SERVER_IP "127.0.0.1"

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cout << "WSAStartup failed" << std::endl;
        return 1;
    }

    SOCKET cli_socket;
    struct sockaddr_in ser_address;
    const char* mesg = "Client is sending greetings!";

    if ((cli_socket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        std::cout << "Error in socket creation: " << WSAGetLastError() << std::endl;
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    ser_address.sin_family = AF_INET;
    ser_address.sin_port = htons(PORT);
    // Substituir inet_pton por inet_addr
    ser_address.sin_addr.s_addr = inet_addr(SERVER_IP);
    if (ser_address.sin_addr.s_addr == INADDR_NONE) {
        std::cout << "Wrong address" << std::endl;
        closesocket(cli_socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    if (connect(cli_socket, (struct sockaddr*)&ser_address, sizeof(ser_address)) == SOCKET_ERROR) {
        std::cout << "Connection failure: " << WSAGetLastError() << std::endl;
        closesocket(cli_socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    send(cli_socket, mesg, strlen(mesg), 0);

    char buf[1024] = {0};
    recv(cli_socket, buf, sizeof(buf), 0);
    std::cout << "Server response: " << buf << std::endl;

    closesocket(cli_socket);
    WSACleanup();
    return 0;
}

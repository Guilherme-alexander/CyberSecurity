#include <iostream>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

#define PORT 8080
#define MAX_BUF_SIZE 1024

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cout << "WSAStartup failed" << endl;
        return 1;
    }

    SOCKET ser_socket, cli_socket;
    struct sockaddr_in ser_address, cli_address;
    char buf[MAX_BUF_SIZE] = {0};

    if ((ser_socket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        cout << "Error in Socket creation: " << WSAGetLastError() << endl;
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    ser_address.sin_family = AF_INET;
    ser_address.sin_addr.s_addr = INADDR_ANY;
    ser_address.sin_port = htons(PORT);

    if (bind(ser_socket, (struct sockaddr*)&ser_address, sizeof(ser_address)) == SOCKET_ERROR) {
        cout << "Failure in bind: " << WSAGetLastError() << endl;
        closesocket(ser_socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    if (listen(ser_socket, 3) == SOCKET_ERROR) {
        cout << "Failed to Listen: " << WSAGetLastError() << endl;
        closesocket(ser_socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    cout << "Server listening on port " << PORT << "...\n";

    int cli_address_len = sizeof(cli_address);
    if ((cli_socket = accept(ser_socket, (struct sockaddr*)&cli_address, &cli_address_len)) == INVALID_SOCKET) {
        cout << "Failed to accept: " << WSAGetLastError() << endl;
        closesocket(ser_socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    recv(cli_socket, buf, MAX_BUF_SIZE, 0);
    cout << "Client's message is: " << buf << endl;

    send(cli_socket, "Server's message", strlen("Server's message"), 0);

    closesocket(cli_socket);
    closesocket(ser_socket);
    WSACleanup();

    return 0;
}

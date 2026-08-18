# Como compilar e executar:

### Linux:

```bash
# Compilar
gcc -Wall -Wextra -O2 -o server server.c
gcc -Wall -Wextra -O2 -o client client.c

# ou usar make
make

# Executar
./server
# Em outro terminal
./client
```

### Windows (com MinGW):

```cmd
# Compilar
gcc -Wall -Wextra -O2 -o server.exe server.c -lws2_32
gcc -Wall -Wextra -O2 -o client.exe client.c -lws2_32

# ou usar make
make

# Executar
server.exe
# Em outro terminal
client.exe
```

### Visual Studio (com CL):

```cmd
cl server.c ws2_32.lib
cl client.c ws2_32.lib
```
## build.bat

```bat
@echo off

echo Building for Windows with MinGW...
gcc -Wall -Wextra -O2 -o server.exe server.c -lws2_32
gcc -Wall -Wextra -O2 -o client.exe client.c -lws2_32
echo Build complete!
echo Run: server.exe
echo Run: client.exe
```

## build.sh

```bash
#!/bin/bash

echo "Building for Linux..."
gcc -Wall -Wextra -O2 -o server server.c
gcc -Wall -Wextra -O2 -o client client.c

echo "Build complete!"
echo "Run: ./server"
echo "Run: ./client"
```

## Makefile

```make
# Makefile
CC = gcc
CFLAGS = -Wall -Wextra -O2

# Detectar sistema operacional
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    TARGET_SERVER = server
    TARGET_CLIENT = client
    CFLAGS += -D_GNU_SOURCE
else
    # Windows (MinGW)
    TARGET_SERVER = server.exe
    TARGET_CLIENT = client.exe
    CFLAGS += -lws2_32
endif

all: $(TARGET_SERVER) $(TARGET_CLIENT)

server: server.c
	$(CC) $(CFLAGS) -o $(TARGET_SERVER) server.c

client: client.c
	$(CC) $(CFLAGS) -o $(TARGET_CLIENT) client.c

clean:
	rm -f $(TARGET_SERVER) $(TARGET_CLIENT)

.PHONY: all clean
```

## warnings

Os warnings que você está vendo são normais e o código vai funcionar!

```cmd
server.c:8: warning: ignoring #pragma comment  [-Wunknown-pragmas]
     #pragma comment(lib, "ws2_32.lib")

client.c:8: warning: ignoring #pragma comment  [-Wunknown-pragmas]
     #pragma comment(lib, "ws2_32.lib")

client.c: In function 'main':
client.c:62:9: warning: implicit declaration of function 'inet_pton'; did you mean 'inet_ntoa'? [-Wimplicit-function-declaration]
     if (inet_pton(AF_INET, SERVER_IP, &ser_address.sin_addr) <= 0) {
         ^~~~~~~~~
         inet_ntoa
```

 * `#pragma comment(lib, "ws2_32.lib")` - Isso é específico do Visual Studio. O MinGW (GCC no Windows) ignora esse pragma, mas você já está linkando a biblioteca com -lws2_32 no build.bat, então está tudo certo!
 * `inet_pton` - No Windows, essa função é mais recente e às vezes o MinGW não a reconhece. Vou corrigir isso.

 ## Solução
  * `#pragma comment` MinGW não usa isso - Remover do código ou usar `-Wno-unknown-pragmas`
  * `inet_pton` Função não reconhecida no Windows - Usar `inet_addr` ou minha função `convert_ip()`

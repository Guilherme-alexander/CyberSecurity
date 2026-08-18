# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# server.ps1
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# .\server.ps1
# Server listening on port 8080...
# Waiting for client connection...
# Client connected from 127.0.0.1:3604
# Client's message is: Client is sending greetings!
# 16
# Sent response: Server's message
# Connection closed
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 

$PORT = 8080
$MAX_BUF_SIZE = 1024

try {
    # Criar socket
    $ser_socket = New-Object System.Net.Sockets.Socket(
        [System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Stream,
        [System.Net.Sockets.ProtocolType]::Tcp
    )
    
    # Permitir reutilização da porta
    $ser_socket.SetSocketOption(
        [System.Net.Sockets.SocketOptionLevel]::Socket,
        [System.Net.Sockets.SocketOptionName]::ReuseAddress,
        $true
    )
    
    # Bind
    $ser_address = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, $PORT)
    $ser_socket.Bind($ser_address)
    
    # Listen
    $ser_socket.Listen(3)
    Write-Host "Server listening on port $PORT..."
    
    # Aceitar conexão
    Write-Host "Waiting for client connection..."
    $cli_socket = $ser_socket.Accept()
    $remote_endpoint = $cli_socket.RemoteEndPoint
    Write-Host "Client connected from $($remote_endpoint.Address):$($remote_endpoint.Port)"
    
    # Receber mensagem do cliente
    $buffer = New-Object Byte[] $MAX_BUF_SIZE
    $received_bytes = $cli_socket.Receive($buffer)
    $message = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $received_bytes)
    Write-Host "Client's message is: $message"
    
    # Enviar resposta
    $response = "Server's message"
    $response_bytes = [System.Text.Encoding]::UTF8.GetBytes($response)
    $cli_socket.Send($response_bytes)
    Write-Host "Sent response: $response"
    
    # Fechar conexões
    $cli_socket.Close()
    $ser_socket.Close()
    Write-Host "Connection closed"
    
} catch {
    Write-Host "Error: $_"
    exit 1
}

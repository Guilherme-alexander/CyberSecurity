# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# client.ps1
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# .\client.ps1
# Connected to server at 127.0.0.1:8080
# 28
# Sent: Client is sending greetings!
# Server response: Server's message
# Connection closed
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 

$PORT = 8080
$SERVER_IP = "127.0.0.1"

try {
    # Criar socket
    $cli_socket = New-Object System.Net.Sockets.Socket(
        [System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Stream,
        [System.Net.Sockets.ProtocolType]::Tcp
    )
    
    # Conectar ao servidor
    $ser_address = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($SERVER_IP), $PORT)
    $cli_socket.Connect($ser_address)
    Write-Host "Connected to server at $SERVER_IP`:$PORT"
    
    # Enviar mensagem
    $message = "Client is sending greetings!"
    $message_bytes = [System.Text.Encoding]::UTF8.GetBytes($message)
    $cli_socket.Send($message_bytes)
    Write-Host "Sent: $message"
    
    # Receber resposta
    $buffer = New-Object Byte[] 1024
    $received_bytes = $cli_socket.Receive($buffer)
    $response = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $received_bytes)
    Write-Host "Server response: $response"
    
    # Fechar conexão
    $cli_socket.Close()
    Write-Host "Connection closed"
    
} catch {
    Write-Host "Error: $_"
    exit 1
}

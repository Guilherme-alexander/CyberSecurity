# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# client_simple.ps1
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# .\client_simple.ps1
# Connected to server at 127.0.0.1:8080
# Sent: Client is sending greetings!
# Server response: Server's message
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 

$PORT = 8080
$SERVER_IP = "127.0.0.1"

try {
    $client = New-Object System.Net.Sockets.TcpClient($SERVER_IP, $PORT)
    Write-Host "Connected to server at $SERVER_IP`:$PORT"
    
    $stream = $client.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    $reader = New-Object System.IO.StreamReader($stream)
    $writer.AutoFlush = $true
    
    # Enviar mensagem
    $message = "Client is sending greetings!"
    $writer.WriteLine($message)
    Write-Host "Sent: $message"
    
    # Receber resposta
    $response = $reader.ReadLine()
    Write-Host "Server response: $response"
    
    $client.Close()
    
} catch {
    Write-Host "Error: $_"
}

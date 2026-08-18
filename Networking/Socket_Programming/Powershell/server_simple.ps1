# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# server_simple.ps1
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# .\server_simple.ps1
# Server listening on port 8080...
# Waiting for client...
# Client connected!
# Client's message is: Client is sending greetings!
# Sent response: Server's message
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 

$PORT = 8080

try {
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $PORT)
    $listener.Start()
    Write-Host "Server listening on port $PORT..."
    
    Write-Host "Waiting for client..."
    $client = $listener.AcceptTcpClient()
    Write-Host "Client connected!"
    
    $stream = $client.GetStream()
    $reader = New-Object System.IO.StreamReader($stream)
    $writer = New-Object System.IO.StreamWriter($stream)
    $writer.AutoFlush = $true
    
    # Receber mensagem
    $message = $reader.ReadLine()
    Write-Host "Client's message is: $message"
    
    # Enviar resposta
    $response = "Server's message"
    $writer.WriteLine($response)
    Write-Host "Sent response: $response"
    
    $client.Close()
    $listener.Stop()
    
} catch {
    Write-Host "Error: $_"
}

@echo off
set HOSTS=C:\Windows\System32\drivers\etc\hosts

:: Verifica Administrador
net session >nul 2>&1 || (echo Sem permissao. Execute como Admin. & pause & exit /b)

:: Adiciona as entradas
echo. >> "%HOSTS%"
echo # SmartScreen Bypass >> "%HOSTS%"
echo 0.0.0.0 telem-edge.smartscreen.microsoft.com dl-edge.smartscreen.microsoft.com nav-edge.smartscreen.microsoft.com safebrowsing.googleapis.com safebrowsing-cache.google.com safebrowsing.google.com sb-ssl.google.com app-edge.smartscreen.microsoft.com >> "%HOSTS%"

:: Limpa cache
ipconfig /flushdns >nul

echo Concluido.
pause

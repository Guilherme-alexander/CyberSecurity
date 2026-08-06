# Pivoting - Guia de Conceitos e Arquitetura

## Índice
1. [O que é Pivoting](#o-que-é-pivoting)
2. [Para que Serve](#para-que-serve)
3. [Fluxo de Funcionamento](#fluxo-de-funcionamento)
4. [Camadas de Rede](#camadas-de-rede)
5. [Arquitetura TCP/IP no Pivoting](#arquitetura-tcpip-no-pivoting)
6. [Cenários e Fluxos](#cenários-e-fluxos)
7. [Modelo de Comunicação](#modelo-de-comunicação)
8. [Resumo Técnico](#resumo-técnico)

---

## O que é Pivoting

Pivoting é uma técnica que usa um sistema comprometido como trampolim para acessar redes e sistemas não diretamente acessíveis.

### Conceito Fundamental

```mermaid
graph LR
    A[Atacante] --> B[Pivô 1]
    B --> C[Pivô 2]
    C --> D[Alvo Final]
```

### Visão Geral

```mermaid
graph TD
    ATK[Atacante] --> WEB[Web Server - Pivô]
    WEB --> DB[(Database)]
    WEB --> APP[App Server]
    WEB --> FS[File Server]
```

---

## Para que Serve

### Objetivos Principais

- **Amplificação de Alcance**: Acessar redes internas não roteáveis, contornar firewalls/NAT
- **Ocultação**: Mascarar origem dos ataques, manter múltiplos pontos de acesso
- **Movimento Lateral**: Explorar confiança entre sistemas, mapear topologia

### Exemplo Visual

```mermaid
graph LR
    ATK[Atacante] -->|Acessível| WEB[Web Server]
    ATK -.->|Não Acessível| DB[(Database)]
    WEB -->|Pivot| DB
```

---

## Fluxo de Funcionamento

### Fluxo Geral

```mermaid
graph TD
    START([Início]) --> A[Reconhecimento]
    A --> B[Escolha do Pivô]
    B --> C[Estabelecer Túnel]
    C --> D[Configurar Proxy]
    D --> E[Exploração]
    E --> F([Fim])
```

### Detalhamento do Fluxo

| Fase | Atividades |
|------|------------|
| **Reconhecimento** | Identificar rede, mapear interfaces, descobrir sistemas |
| **Escolha do Pivô** | Selecionar host, verificar encaminhamento, validar conectividade |
| **Estabelecer Túnel** | SSH (-D/-L/-R), VPN, DNS/ICMP Tunneling |
| **Configurar Proxy** | Proxychains, port forwarding, roteamento, NAT |
| **Exploração** | Scan, enumeração, exploração, movimento lateral |

### Matriz de Decisão

```mermaid
graph TD
    INICIO([Início]) --> Q1{IP Público?}
    Q1 -->|SIM| SSH[SSH -D/-L/-w]
    Q1 -->|NÃO| Q2{Conexão Externa?}
    Q2 -->|SIM| Q3{Protocolo?}
    Q3 -->|TCP| SSH_R[SSH -R/rpivot]
    Q3 -->|DNS| DNS[Iodine/Dnscat2]
    Q3 -->|HTTP| HTTP[Cntlm/rpivot]
    Q2 -->|NÃO| Q4{ICMP?}
    Q4 -->|SIM| ICMP[Hans]
    Q4 -->|NÃO| DNS2[Iodine/Dnscat2]
    SSH --> CONFIG[Configurar]
    SSH_R --> CONFIG
    DNS --> CONFIG
    HTTP --> CONFIG
    ICMP --> CONFIG
    DNS2 --> CONFIG
    CONFIG --> TEST[Testar]
    TEST --> SCAN[Scan]
    SCAN --> FIM([Fim])
```

---

## Camadas de Rede

### Modelo OSI Simplificado

```mermaid
graph TD
    A7[7. Aplicação] --> A6[6. Apresentação]
    A6 --> A5[5. Sessão]
    A5 --> A4[4. Transporte]
    A4 --> A3[3. Rede]
    A3 --> A2[2. Enlace]
    A2 --> A1[1. Física]
```

### Detalhamento por Camada

| Camada | Protocolos | Função no Pivoting |
|--------|------------|-------------------|
| **Aplicação** | HTTP, SSH, DNS, SMB, RDP | Ferramentas de enumeração e serviços alvo |
| **Apresentação** | SSL/TLS, SSH | Encapsulamento e criptografia de túneis |
| **Sessão** | SOCKS5, SSH, NetBIOS | Gerenciamento de conexões e autenticação |
| **Transporte** | TCP, UDP | Port forwarding e encaminhamento de pacotes |
| **Rede** | IP, ICMP, ARP | Roteamento e túneis de camada 3 (TUN) |
| **Enlace** | Ethernet, MAC | ARP spoofing e VLAN hopping |
| **Física** | Cabo, Fibra, WiFi | Acesso físico ao ambiente |

### Protocolos Comuns em Pivoting

| Categoria | Protocolos/Ferramentas | Características |
|-----------|----------------------|-----------------|
| **Túnel** | SSH, DNS (Iodine/Dnscat2), ICMP (Hans), OpenVPN | Transporte através de firewalls/NAT |
| **Transporte** | TCP, UDP | Conexões orientadas ou não orientadas |
| **Proxy** | SOCKS4/5, HTTP CONNECT, Cntlm | Encaminhamento de tráfego |

---

## Arquitetura TCP/IP no Pivoting

### Conexão TCP via Proxy

```mermaid
sequenceDiagram
    participant C as Cliente
    participant P as Proxy
    participant S as Servidor
    
    C->>P: CONNECT proxy:1080
    P-->>C: 200 OK
    C->>P: SYN
    P->>S: SYN
    S-->>P: SYN-ACK
    P-->>C: SYN-ACK
    C->>P: ACK
    P->>S: ACK
    C->>P: DATA
    P->>S: DATA
    S-->>P: DATA
    P-->>C: DATA
```

### Encapsulamento de Túnel VPN

```mermaid
graph TD
    subgraph EXT[Pacote Externo]
        ETH[Ethernet]
        IP_EXT[IP Externo]
        TCP_EXT[TCP Externo]
        SSH[SSH Encriptado]
    end
    
    subgraph INT[Pacote Interno]
        IP_INT[IP Interno]
        TCP_INT[TCP Interno]
        DATA[Dados]
    end
    
    ETH --> IP_EXT --> TCP_EXT --> SSH
    SSH --> IP_INT --> TCP_INT --> DATA
```

---

## Cenários e Fluxos

### 1. Alvo com IP Público

**Arquitetura:**
```mermaid
graph TD
    ATK[Atacante] -->|SSH -D| PIVO[Pivô 203.0.113.10]
    PIVO -->|SOCKS| ALVO1[Alvo 192.168.1.100]
    PIVO -->|SOCKS| ALVO2[Alvo 192.168.1.200]
```

**Fluxo de Pacotes:**
```mermaid
sequenceDiagram
    participant ATK as Atacante
    participant PIVO as Pivô
    participant ALVO as Alvo
    
    ATK->>PIVO: SSH -D 1080
    Note right of PIVO: Túnel SOCKS ativo
    ATK->>PIVO: CONNECT 192.168.1.100:445
    PIVO->>ALVO: SYN
    ALVO-->>PIVO: SYN-ACK
    PIVO-->>ATK: SYN-ACK
    ATK->>PIVO: SMB Request
    PIVO->>ALVO: SMB Request
    ALVO-->>PIVO: SMB Response
    PIVO-->>ATK: SMB Response
```

### 2. Alvo com IP Privado (NAT)

**Arquitetura:**
```mermaid
graph TD
    ATK[Atacante] -->|SSH -R| NAT[Firewall/NAT]
    NAT --> PIVO[Pivô 10.0.0.5]
    PIVO --> ALVO[Alvo 10.10.10.5]
```

**Fluxo de Conexão Reversa:**
```mermaid
sequenceDiagram
    participant ATK as Atacante
    participant NAT as Firewall/NAT
    participant PIVO as Pivô
    participant ALVO as Alvo
    
    PIVO->>NAT: SSH -R 31337
    NAT->>ATK: Conexão Reversa
    Note right of ATK: Proxy em 127.0.0.1:31337
    ATK->>NAT: CONNECT 10.10.10.5:3389
    NAT->>PIVO: Encapsulado
    PIVO->>ALVO: SYN
    ALVO-->>PIVO: SYN-ACK
    PIVO-->>NAT: SYN-ACK
    NAT-->>ATK: SYN-ACK
```

### 3. Proxy Corporativo

**Arquitetura:**
```mermaid
graph TD
    ATK[Atacante] -->|NTLM| PROXY[Proxy 10.0.0.10:8080]
    PROXY -->|HTTP CONNECT| PIVO[Pivô 10.10.10.5]
    PIVO --> ALVO[Alvo 192.168.1.100]
```

**Fluxo de Autenticação NTLM:**
```mermaid
sequenceDiagram
    participant C as Cliente
    participant P as Proxy
    participant S as Servidor
    
    C->>P: GET / HTTP/1.1
    P-->>C: 407 NTLM Challenge
    C->>P: GET / NTLM Response
    P-->>C: 200 OK
    C->>P: SSH CONNECT
    P->>S: SSH Connection
```

### 4. DNS Tunneling

**Arquitetura:**
```mermaid
graph TD
    ATK[Atacante DNS Server] -->|Queries| NS[Authoritative NS]
    NS -->|Responses| PIVO[Pivô iodine/dnscat2]
    PIVO --> ALVO[Alvo 10.10.10.5]
```

### 5. ICMP Tunneling

**Arquitetura:**
```mermaid
graph TD
    ATK[Atacante ICMP Server] -->|ICMP Echo| FW[Firewall]
    FW -->|ICMP Passthrough| PIVO[Pivô hans client]
    PIVO --> ALVO[Alvo 10.10.10.5]
```

---

## Modelo de Comunicação

### Mapeamento de Portas e Protocolos

```mermaid
graph LR
    subgraph ATK[Atacante]
        SSH_CLI[SSH Client]
        APP[Aplicação]
        PROXY[Proxy Local]
    end
    
    subgraph TUNEL[Túnel SSH]
        SSH[SSH Tunnel]
    end
    
    subgraph PIVO[Pivô]
        SSH_SRV[SSH Server:22]
        SOCKS[SOCKS:1080]
        FW[Encaminhador]
    end
    
    subgraph ALVO[Alvo]
        SERVICO[Serviço]
    end
    
    SSH_CLI --> SSH
    APP --> PROXY --> SSH
    SSH --> SSH_SRV
    SSH_SRV --> SOCKS --> FW --> SERVICO
```

### Tipos de Tráfego

```mermaid
graph TD
    T1[1. Direto: Atacante → Pivô]
    T2[2. Proxy: Atacante → Proxy → Pivô → Alvo]
    T3[3. Túnel: Atacante ↔ Túnel ↔ Pivô ↔ Alvo]
    T4[4. Reverso: Atacante ↔ Túnel Reverso ↔ Pivô ↔ Alvo]
    T5[5. Mascarado: Atacante ↔ DNS/ICMP ↔ Pivô ↔ Alvo]
    
    T1 --> T2 --> T3
    T3 --> T4
    T3 --> T5
```

### Camadas de Abstração

```mermaid
graph TD
    L5[5. Aplicação: Ferramentas] --> L4[4. Proxy: Proxychains/SOCKS]
    L4 --> L3[3. Túnel: SSH/DNS/ICMP]
    L3 --> L2[2. Rede: TCP/IP/UDP/ICMP]
    L2 --> L1[1. Física: Ethernet/WiFi]
```

---

## Resumo Técnico

### Características por Tipo de Pivoting

| Tipo | Protocolo | Camada | Direção | Root | Velocidade |
|------|-----------|--------|---------|------|------------|
| **SSH -D** | TCP | Aplicação | Direta | Não | Alta |
| **SSH -L** | TCP | Transporte | Direta | Não | Alta |
| **SSH -R** | TCP | Transporte | Reversa | Não | Alta |
| **SSH -w** | IP | Rede | Direta | Sim | Alta |
| **SOCKS** | TCP | Sessão | Direta | Não | Alta |
| **HTTP Proxy** | TCP | Aplicação | Direta | Não | Média |
| **DNS Tunnel** | UDP | Aplicação | Reversa | Não | Baixa |
| **ICMP Tunnel** | ICMP | Rede | Reversa | Sim | Média |
| **OpenVPN** | TCP/UDP | Rede | Direta | Sim | Alta |
| **Cntlm** | TCP | Aplicação | Direta | Não | Alta |

### Visão Geral de Velocidade vs. Estabilidade

| Tipo | Velocidade | Estabilidade | Uso Típico |
|------|------------|--------------|------------|
| **SSH -D/L/R/w** | Alta | Alta | Acesso SSH direto ou reverso |
| **SOCKS/HTTP** | Média-Alta | Média-Alta | Ambientes com proxies corporativos |
| **DNS/ICMP** | Baixa-Média | Média | Firewall restritivo (apenas DNS/ICMP) |
| **OpenVPN** | Alta | Alta | Tunelamento de camada 3 |

### Pontos de Verificação

```mermaid
graph LR
    PRE[Antes] --> DUR[Durante] --> POS[Depois]
```

| Fase | Itens |
|------|-------|
| **Antes** | Mapear topologia, identificar firewall, testar conectividade, avaliar privilégios |
| **Durante** | Escolher técnica, criar canal, configurar ferramentas, validar roteamento |
| **Depois** | Automatizar, ocultar tráfego, expandir pivô, documentar |

### Comandos Rápidos por Cenário

| Cenário | Comando |
|---------|---------|
| **IP Público (SOCKS)** | `ssh user@host -D 1080` |
| **IP Público (Port Forward)** | `ssh user@host -L 445:192.168.1.1:445` |
| **NAT (Reverse)** | `ssh user@server -R 31337:127.0.0.1:31337` |
| **NAT (rpivot)** | `python client.py --server-ip IP --server-port 9999` |
| **Proxy NTLM (rpivot)** | `python client.py --ntlm-proxy-ip IP --username User` |
| **Proxy NTLM (Cntlm)** | `./cntlm -c config.conf` |
| **DNS Tunnel** | `iodine -f -P pass tunnel.domain.com` |
| **ICMP Tunnel** | `./hans -f -c server_ip -p pass` |

# Fluxo de conexão SSH


## Fluxo de conexão

```mermaid
sequenceDiagram
    participant Client
    participant Server

    Client->>Server: ssh admin@site.com
    Server-->>Client: Solicita autenticação

    alt Senha
        Client->>Server: Envia senha
    else Chave SSH
        Client->>Server: Assina desafio com Private Key
        Server->>Server: Verifica Public Key
    end

    Server-->>Client: Login realizado
```


Resultado:

```text
Cliente  --->  Servidor
      Autenticação
      Senha ou Chave
```

---

# Funcionamento das chaves SSH


```mermaid
flowchart LR

A[Cliente]

subgraph CLIENT
B[id_ed25519<br/>Private Key]
C[id_ed25519.pub<br/>Public Key]
end

subgraph SERVER
D[authorized_keys]
end

C --> D

style B fill:#ffdddd
style C fill:#ddffdd
style D fill:#ddddff
```

Fica bem intuitivo:

```
Private Key
      │
      │ Nunca sai do cliente
      │
Public Key ─────────────► authorized_keys
```

---

# Processo do ssh-copy-id


```mermaid
flowchart TD

A[Gerar chave<br>ssh-keygen]

B[Copiar chave pública<br>ssh-copy-id]

C[Servidor adiciona<br>authorized_keys]

D[Conectar sem senha]

A --> B
B --> C
C --> D
```

---

# Fluxo do SCP

```mermaid
flowchart LR

subgraph CLIENTE
A[Document.pdf]
end

subgraph SERVIDOR
B[/home/admin/docs/]
end

A -- Upload --> B
B -- Download --> A
```

---

# Estrutura dos arquivos

```mermaid
flowchart TD

HOME["~/.ssh"]

HOME --> A[id_ed25519]
HOME --> B[id_ed25519.pub]
HOME --> C[known_hosts]
HOME --> D[config]

SERVER["Servidor"]

SERVER --> E[authorized_keys]
```

---

# Processo completo de login

```mermaid
flowchart TD

A[Instalar SSH]

A --> B[Iniciar Serviço]

B --> C[Gerar Chaves]

C --> D[Copiar Public Key]

D --> E[Configurar Servidor]

E --> F[ssh usuario@host]

F --> G[Conexão Segura]
```

---

# Configuração do SSH

```mermaid
flowchart TD

A[Editar sshd_config]

A --> B[Alterar Porta]

A --> C[Desabilitar Root]

A --> D[AllowUsers]

B --> E[Restart SSH]
C --> E
D --> E
```

---

## Comparação entre autenticação por senha e por chave

```mermaid
flowchart LR

LOGIN[Login SSH]

LOGIN --> SENHA[Senha]

LOGIN --> CHAVE[Chave SSH]

SENHA --> A[Mais simples]
SENHA --> B[Menos segura]

CHAVE --> C[Mais segura]
CHAVE --> D[Mais rápida]
```

---

## Organização que eu usaria

```text
SSH
│
├── 📦 Instalação
│      ├── apt install
│      ├── systemctl
│      └── enable
│
├── 🔐 Conexão
│      ├── Sintaxe
│      ├── Exemplos
│      └── Fluxograma Mermaid
│
├── 🔑 SSH Keys
│      ├── ssh-keygen
│      ├── Estrutura
│      ├── Mermaid
│      └── ssh-copy-id
│
├── 📂 SCP
│      ├── Upload
│      ├── Download
│      ├── Flags
│      └── Mermaid
│
├── ⚙️ Configuração
│      ├── sshd_config
│      ├── Root Login
│      ├── Porta
│      ├── AllowUsers
│      └── Mermaid
│
└── 📖 Referência
       ├── ~/.ssh
       ├── authorized_keys
       ├── known_hosts
       └── config

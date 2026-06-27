# SSH

Guia rápido de utilização do SSH no Linux.

---

# Instalação

## Instalar o OpenSSH Server

```bash
sudo apt install openssh-server
```

## Iniciar o serviço

```bash
sudo systemctl start ssh
```

## Verificar status

```bash
sudo systemctl status ssh
```

## Habilitar inicialização automática

```bash
sudo systemctl enable ssh
```

---

# Conexão SSH

## Porta padrão

```
22
```

## Sintaxe

```bash
ssh <USUARIO>@<HOST>

# Porta personalizada
ssh <USUARIO>@<HOST> -p <PORTA>
```

## Exemplos

```bash
ssh ubuntu@127.0.0.1

ssh admin@site.com -p 2222
```

Saída esperada:

```text
user@debian:~$ ssh admin@site.com -p 2222

admin@site.com's password:
```

---

# Chaves SSH (SSH-Keygen)

## Gerar um par de chaves

```bash
ssh-keygen -t ed25519 -C "my_keys"
```

Durante a criação:

```text
Enter file in which to save the key:
/home/user/.ssh/id_ed25519

Enter passphrase (empty for no passphrase):
<OPCIONAL>

Enter same passphrase again:
<CONFIRMAR SENHA>
```

Arquivos gerados:

```
~/.ssh/id_ed25519        -> Chave Privada (NUNCA compartilhe)
~/.ssh/id_ed25519.pub    -> Chave Pública
```

### Funcionamento

```
CLIENTE
│
├── id_ed25519        (Private Key)
└── id_ed25519.pub    (Public Key)
            │
            ▼
SERVIDOR
└── ~/.ssh/authorized_keys
```

> A chave **privada permanece no cliente**.
>
> Apenas a **chave pública** é copiada para o servidor.

---

# Copiar chave pública para o servidor

Utilizando `ssh-copy-id`:

```bash
ssh-copy-id -p 2222 admin@site.com
```

Será solicitada a senha do usuário apenas uma vez.

Depois disso:

```bash
ssh admin@site.com -p 2222
```

---

# SCP (Secure Copy)

Permite copiar arquivos utilizando SSH.

---

## Sintaxe

```bash
scp <ORIGEM> <DESTINO>
```

---

## Upload

**Cliente → Servidor**

```bash
scp Document.pdf admin@site.com:/home/admin/

scp Document.pdf admin@site.com:/home/admin/docs/
```

---

## Download

**Servidor → Cliente**

Arquivo:

```bash
scp admin@site.com:/home/admin/docs/Document.pdf .
```

Diretório:

```bash
scp -r admin@site.com:/home/admin/docs/ .
```

---

# Principais opções

| Opção | Descrição |
|--------|-----------|
| `-P` | Porta do SSH |
| `-r` | Copiar diretórios recursivamente |
| `-C` | Compressão durante a transferência |
| `-p` | Preservar permissões e timestamps |

Exemplo:

```bash
scp -P 2222 -C arquivo.zip admin@site.com:/home/admin/
```

---

# Configuração do servidor SSH

Arquivo de configuração:

```bash
sudo nano /etc/ssh/sshd_config
```

## Desabilitar login do Root

Antes:

```text
PermitRootLogin yes
```

Depois:

```text
PermitRootLogin no
```

---

## Alterar porta padrão

Antes:

```text
Port 22
```

Depois:

```text
Port 2222
```

---

## Permitir apenas usuários específicos

```text
AllowUsers user
```

Também é possível permitir vários usuários:

```text
AllowUsers user admin backup
```

---

## Reiniciar o serviço

```bash
sudo systemctl restart ssh
```

---

# Comandos úteis

Verificar porta em uso:

```bash
ss -tulpn | grep ssh
```

Ver conexões SSH ativas:

```bash
who
```

ou

```bash
w
```

Ver fingerprint da chave pública:

```bash
ssh-keygen -lf ~/.ssh/id_ed25519.pub
```

Conectar utilizando uma chave específica:

```bash
ssh -i ~/.ssh/id_ed25519 admin@site.com
```

---

# Estrutura dos arquivos SSH

```text
~/.ssh/
├── id_ed25519          <- Chave privada
├── id_ed25519.pub      <- Chave pública
├── known_hosts         <- Hosts conhecidos
└── config              <- Configuração do cliente SSH
```

No servidor:

```text
~/.ssh/
└── authorized_keys
```

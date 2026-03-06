# 🛠️ WINRAR CRACKER v3.1 - Ferramenta de RedTeam para Quebra de Senhas

![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

## 📋 Descrição

Ferramenta profissional de **Red Team** desenvolvida em Python para testes de penetração e recuperação de acesso a arquivos protegidos por senha nos formatos ZIP e RAR. Utiliza o WinRAR em modo silencioso para realizar ataques de dicionário de forma eficiente e discreta.

### 🎯 Propósito Educacional
> ⚠️ **AVISO LEGAL**: Esta ferramenta foi desenvolvida exclusivamente para fins educacionais, testes de penetração autorizados e recuperação de arquivos próprios. O uso não autorizado pode violar leis locais e internacionais.

## ✨ Características

- 🔍 **Ataque de Dicionário** - Testa múltiplas senhas a partir de wordlists
- ⚡ **Suporte a Threads** - Processamento paralelo para maior performance
- 🎭 **Modo Silencioso** - Opera sem janelas ou pop-ups utilizando parâmetros `-ibck` e `-inul`
- 💬 **Modo Interativo** - Interface amigável para uso rápido
- 🎨 **Output Colorido** - Feedback visual com cores para fácil identificação de resultados
- 📊 **Métricas em Tempo Real** - Exibição de status codes e timestamps

## 🚀 Instalação

### Pré-requisitos

```bash
# Windows com WinRAR instalado (obrigatório)
# WinRAR padrão: C:\Program Files\WinRAR\WinRAR.exe

# Instalar dependências Python
pip install colorama
```

## Modo Interativo

```bash
python cracker.py
```

### EXEMPLO

```cmd
$ python cracker.py

[Modo Interativo]
Arquivo .zip/.rar: backup.rar
Wordlist (ou deixe vazio): rockyou.txt
Senha manual (ou deixe vazio): 
Número de threads (default 2): 4

[INFO] Wordlist: rockyou.txt
[INFO] Tamanho: 134.22 MB
============================================================
[!] [STATUS CODE]: 3 [TIME] 2024-01-15 14:23:45
[✘] Errada: 123456
...
[!] STATUS CODE: 0 TIME: 2024-01-15 14:24:12
[✔] Senha correta: admin123
```

## Linha de Comando

```bash
# Testar senha única
python cracker.py arquivo.rar -p "minha_senha"

# Ataque com wordlist
python cracker.py arquivo.zip -w wordlist.txt

# Especificar número de threads
python cracker.py arquivo.rar -w wordlist.txt -t 4
```

---

### Sintaxe Completa

```bash
cracker.py [-h] [-w WORDLIST] [-p PASSWORD] [-t THREADS] [file]
```

---

## Argumento Descrição

```bash
file	Arquivo .zip ou .rar alvo
-w, --wordlist	Caminho para arquivo de wordlist
-p, --password	Testar senha específica
-t, --threads	Número de threads (padrão: 2)
-h, --help	Exibir ajuda
```

---

## ⚙️ Funcionamento Interno Comandos WinRAR Utilizados

```bash
# Comando base para teste silencioso
WinRAR.exe x -pSENHA -ibck -inul arquivo.rar

# Parâmetros explicados:
# x  → Extrair arquivos
# -p → Especificar senha
# -ibck → Modo background (sem janelas)
# -inul → Sem saída no console
```

## Códigos de Retorno e Código	Significados:

```cmd
✅ 0 Senha correta - Extração bem-sucedida.
❌ 3 Senha incorreta.
❌ 1 até 255 Outros	⚠️ Erro genérico.
```

---

## 🛡️ Medidas de Segurança
* ✅ Execução em modo silencioso para evitar detecção
* ✅ Sem criação de arquivos temporários
* ✅ Tratamento de interrupções (CTRL+C)
* ✅ Validação de entrada de dados

## ⚠️ Limitações
* 🔹 Funciona apenas no Windows com WinRAR instalado
* 🔹 Não suporta arquivos com criptografia AES-256
* 🔹 Limitado à velocidade de processamento do WinRAR

---

**Desenvolvido para fins educacionais e testes de penetração autorizados.**
**Desenvolvido com ❤️ para a comunidade de testes de penetração/Pentest** <br/>

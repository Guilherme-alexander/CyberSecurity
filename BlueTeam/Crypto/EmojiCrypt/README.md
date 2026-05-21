# 🔐 EmojiCrypt 

> Secure emoji-based message encryption using Fernet, PBKDF2, and custom emoji encoding.

<br/>

![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)

---

## 📖 Overview

EmojiCrypt  is a lightweight Python tool that securely encrypts messages and transforms encrypted byte data into harmless-looking emoji sequences.

The project combines:

- 🔐 Fernet authenticated encryption
- 🔑 PBKDF2 password-based key derivation
- 🧂 Random salt generation
- 😊 Custom emoji encoding layer

This allows sensitive text to be visually disguised as normal emoji strings while remaining strongly encrypted underneath.

---

## ✨ Features

- 🔐 Fernet encryption (AES + HMAC)
- 🔑 PBKDF2-HMAC-SHA256 key derivation
- 🧂 Random salt for every encryption
- 😊 Emoji-based payload encoding
- 🔄 Full encryption/decryption workflow
- 🖥️ Simple CLI interface
- 📦 Lightweight and dependency minimal

---

## 🧠 How It Works

### Encryption Flow

```text
Plaintext Message
        ↓
Password Input
        ↓
PBKDF2 Key Derivation
        ↓
Fernet Encryption
        ↓
Encrypted Bytes
        ↓
Emoji Encoding Layer
        ↓
Emoji Ciphertext
```

---

## 📸 Example

### Plaintext

```text
hello world
```

### Encrypted Emoji Output

```text
🙈🚗🛭🚘🛏🙋🚞🙟🛳🚀🙂🙉...
```

---

## 🚀 Installation

<details>
<summary>Clone repository</summary>

```bash
git clone https://github.com/Guilherme-alexander/EmojiCrypt .git
cd EmojiCrypt 
```

</details>

<details>
<summary>Install dependencies</summary>

```bash
pip install -r requirements.txt
```

</details>

---

## 📦 Requirements

```text
cryptography
```

---

## ▶️ Usage

Run the tool:

```bash
python main.py
```

---

## 🖥️ Example Interface

```text
–––––––––––––––––––––––––––––––––––––––––––––––
           🔐 EmojiCrypt O TOOL 🔐
     Strong encryption + hidden emoji messages
                BY: @Guilherme-alexander
–––––––––––––––––––––––––––––––––––––––––––––––

1 - Encrypt
2 - Decrypt
0 - Exit
```

---

## 🔐 Cryptography Details

### Encryption

The project uses:

```text
Fernet (AES-128-CBC + HMAC-SHA256)
```

Provided by the Python `cryptography` library.

---

### Key Derivation

Keys are derived using:

```text
PBKDF2-HMAC-SHA256
```

with:

- 100,000 iterations
- random 16-byte salt

---

### Emoji Encoding Layer

Encrypted byte values are converted into emoji Unicode characters using:

```python
chr(BASE_EMOJI + byte)
```

This encoding layer is designed for visual obfuscation and transport convenience.

---

## ⚠️ Security Notes

- Emoji encoding is NOT encryption
- Security comes from Fernet encryption
- Always use strong passwords
- Each encryption uses a unique random salt
- Encrypted output size is larger due to:
  - Fernet metadata
  - HMAC
  - IV generation
  - emoji encoding overhead

---

## 📁 Repository Structure

```text
RedTeam/
└── Crypto/
    └── EmojiCrypt/
        ├── main.py
        ├── README.md
        ├── requirements.txt
        └── examples/
```

---

## 🛠️ Future Improvements

- File encryption support
- Binary payload support
- QR-code export
- Compression support
- GUI version
- Multi-language support
- Custom emoji alphabets

---

## 🎯 Use Cases

- Secure hidden messages
- Fun encrypted communication
- Cryptography learning
- Unicode/emoji encoding research
- Security education
- CTF challenges

---

## 📜 License

MIT License

---

## 👨‍💻 Author

GitHub:  
[@Guilherme-alexander](https://github.com/Guilherme-alexander)

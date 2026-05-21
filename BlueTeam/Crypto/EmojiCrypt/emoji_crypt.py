"""
EmojiCrypt - Secure Emoji-Based Encryption Tool

This project allows users to encrypt and hide messages inside emoji sequences
using strong cryptography. It combines Fernet (AES + HMAC) encryption with a
custom emoji encoding layer, transforming encrypted byte data into visually
harmless emoji strings.

Due to encryption overhead, even small messages (e.g., "test") can result in
100+ bytes of encrypted data, which are then represented as emoji characters.

GitHub Repository:
https://github.com/Guilherme-alexander/CyberSecurity/BlueTeam/Crypto/EmojiCrypt

Author:
https://github.com/Guilherme-alexander
"""

import base64
import os
import hashlib
from cryptography.fernet import Fernet

BASE_EMOJI = 0x1F600


def banner():
    print("–" * 47)
    print(" " * 11, "🔐 EMOJI CRYPTO TOOL 🔐")
    print(" " * 2, "Strong encryption + hidden emoji messages")
    print(" " * 15, "BY: @Guilherme-alexander")
    print("–" * 47)


def derive_key(password, salt):
    kdf = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        100000
    )
    return base64.urlsafe_b64encode(kdf)


def text_to_emoji(data):
    return "".join(chr(BASE_EMOJI + b) for b in data)


def emoji_to_text(emojis):
    return bytes([ord(e) - BASE_EMOJI for e in emojis])


def encrypt():
    text = input("Enter message: ")
    password = input("Enter password: ")

    salt = os.urandom(16)
    key = derive_key(password, salt)

    f = Fernet(key)
    token = f.encrypt(text.encode())

    payload = salt + token
    emoji_msg = text_to_emoji(payload)

    print("\n🔒 Encrypted message:")
    print(emoji_msg)


def decrypt():
    emoji_msg = input("Paste emoji message: ")
    password = input("Enter password: ")

    try:
        data = emoji_to_text(emoji_msg)

        salt = data[:16]
        token = data[16:]

        key = derive_key(password, salt)
        f = Fernet(key)

        decrypted = f.decrypt(token).decode()

        print("\n🔓 Decrypted message:")
        print(decrypted)

    except Exception:
        print("\n❌ Error: invalid password or corrupted message.")


def menu():
    while True:
        print("\n1 - Encrypt")
        print("2 - Decrypt")
        print("0 - Exit")

        choice = input("Choose: ")

        if choice == "1":
            encrypt()
        elif choice == "2":
            decrypt()
        elif choice == "0":
            print("Exiting...")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    banner()
    menu()

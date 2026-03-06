#!/usr/bin/env python3

# DESENVOLVEDOR: Guilherme-alexander (GITHUB)

import subprocess
import os
import sys
import time
import shutil
import argparse
import subprocess

from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style, Back
from datetime import datetime

init(autoreset=True)

BANNER = f"""
{Fore.RED}{Style.BRIGHT}
 __      _____ _  _ ___    _   ___        
 \ \    / /_ _| \| | _ \  /_\ | _ \       
  \ \/\/ / | || .` |   / / _ \|   /       
  _\_/\_/ |___|_|\_|_|_\/_/_\_\_|_\_ ___  
 | _ \/_\ / __/ __\ \    / / _ \| _ \   \ 
 |  _/ _ \\__ \__ \\ \/\/ / (_) |   / |) |
 |_|/_/_\_\___/___/_\_/\_/_\___/|_|_\___/ 
  / __| _ \  /_\ / __| |/ / __| _ \       
 | (__|   / / _ \ (__| ' <| _||   /       
  \___|_|_\/_/ \_\___|_|\_\___|_|_\       
                                                      
{Fore.YELLOW}     WINRAR PASSWORD CRACKER v3.1 {Style.RESET_ALL}
"""

timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def command_attack(password, target_file):
    cmd = [
        "WinRAR.exe",
        "x",
        "-p" + password,
        "-ibck",
        "-inul",
        target_file
    ]

    resultado = subprocess.run(cmd)
    print("="*60)

    if resultado.returncode == 0:
        print(f"{Fore.YELLOW}{Style.BRIGHT}[!] STATUS CODE: {resultado.returncode} TIME: {timestamp} {Style.RESET_ALL}")
        print(f"{Fore.GREEN}{Style.BRIGHT}[✔] Senha correta: {password} {Style.RESET_ALL}")
        return True

    elif resultado.returncode == 3:
        print(f"{Fore.YELLOW}{Style.BRIGHT}[!] [STATUS CODE]: {resultado.returncode} [TIME] {timestamp} {Style.RESET_ALL}")
        print(f"{Fore.RED}{Style.BRIGHT}[✘] Errada: {password} {Style.RESET_ALL}")
        return False

    else:
        print(f"{Fore.YELLOW}{Style.BRIGHT}[!] STATUS CODE: {resultado.returncode} TIME: {timestamp} {Style.RESET_ALL}")
        print(f"{Fore.RED}{Style.BRIGHT}[✘] PASSWORD: {password} {Style.RESET_ALL}")
        return False


import os

def format_size(bytes_size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024


def start_wordlist_attack(wordlist, target_file):
    try:
        # 📦 Mostrar tamanho da wordlist
        size_bytes = os.path.getsize(wordlist)
        formatted_size = format_size(size_bytes)

        print("=" * 60)
        print(f"[INFO] Wordlist: {wordlist}")
        print(f"[INFO] Tamanho: {formatted_size}")
        print("=" * 60)

        with open(wordlist, "r", encoding="utf-8") as f:
            for linha in f:
                senha = linha.strip()
                if not senha:
                    continue

                if command_attack(senha, target_file):
                    print("Encerrando execução...")
                    break

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrompido no meio da wordlist.{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='ZIP/RAR Cracker v3.0')

    parser.add_argument('file', nargs='?', help='Arquivo .zip/.rar')
    parser.add_argument('-w', '--wordlist', help='Wordlist path')
    parser.add_argument('-p', '--password', help='Teste senha manual')
    parser.add_argument('-t', '--threads', type=int, default=2, help='Threads')

    args = parser.parse_args()

    print(BANNER)

    if len(sys.argv) == 1:
        print(f"{Fore.CYAN}[Modo Interativo]{Style.RESET_ALL}")

        target_file = input("Arquivo .zip/.rar: ").strip()
        wordlist = input("Wordlist (ou deixe vazio): ").strip()
        password = input("Senha manual (ou deixe vazio): ").strip()
        threads = input("Número de threads (default 2): ").strip()

        if threads.isdigit():
            args.threads = int(threads)

        if password:
            command_attack(password, target_file)
            return

        if wordlist:
            start_wordlist_attack(wordlist, target_file)
            return

        print("Nenhuma opção válida fornecida.")
        return

    if args.password:
        command_attack(args.password, args.file)
        return

    if args.wordlist:
        start_wordlist_attack(args.wordlist, args.file)
    else:
        print("Você precisa fornecer -w ou -p")


if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print("="*40)
        print(f"\n{Fore.RED}{Style.BRIGHT}[!] Ataque interrompido pelo usuário (CTRL+C){Style.RESET_ALL}")
        sys.exit(0)

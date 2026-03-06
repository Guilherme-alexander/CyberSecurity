import os
import subprocess
import colorama
from colorama import Fore, Style

colorama.init()

print("========== START ANÁLISE ==========")

PDFfile = input("PATH to PDF File: ")

if not os.path.exists(PDFfile):
    print(Fore.RED + "❌ Arquivo não encontrado!" + Style.RESET_ALL)
    exit()

print(Fore.CYAN + "\n🔍 SCANNER 1 - Análise Básica" + Style.RESET_ALL)
try:
    subprocess.run(['python', 'PDFScan1.py', PDFfile], check=True)
except subprocess.CalledProcessError:
    print(Fore.YELLOW + "⚠️  Scanner 1 com problemas, continuando com outros scanners..." + Style.RESET_ALL)

print(Fore.CYAN + "\n🔍 SCANNER 2 - Análise Inteligente" + Style.RESET_ALL)
subprocess.run(['python', 'PDFScan2.py', PDFfile])

optionAPI = input("\nUse API Virus Total (y) Yes or (n) Not ? ").lower()

if optionAPI == "y" or optionAPI == "yes":

    API = "API_KEY_VIRUS_TOTAL" # << SET KEY !!!
    
    if API:
        print(Fore.CYAN + "\n🔍 SCANNER 3 - Análise com VirusTotal" + Style.RESET_ALL)

        subprocess.run(['python', 'PDFScan3.py', PDFfile, '--vt-api', API])
        
        check_urls = input("\nVerificar URLs também? (y/n): ").lower()
        if check_urls == 'y':
            subprocess.run(['python', 'PDFScan3.py', PDFfile, '--vt-api', API, '--check-urls'])
        
        subprocess.run(['python', 'PDFScan3.py', PDFfile, '--vt-api', API, '--output', 'relatorio.json'])
    else:
        print(Fore.RED + "❌ API Key não fornecida!" + Style.RESET_ALL)

elif optionAPI == "n" or optionAPI == "not":
    print("Not Using VirusTotal API!")
else:
    print("Opção inválida. Pulando VirusTotal.")

print(Fore.GREEN + "\n✅ Análise concluída!" + Style.RESET_ALL)

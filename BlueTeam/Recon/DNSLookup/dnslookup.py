# Guilherme-Alexander

import argparse
import dns.resolver

class Color:
	BLACK = "\033[30m"
	RED = "\033[31m"
	GREEN = "\033[32m"
	YELLOW = "\033[33m"
	BLUE = "\033[34m"
	PURPLE = "\033[35m"
	CYAN = "\033[36m"
	WHITE = "\033[37m"

	# cores brilhantes
	BRIGHT_RED = "\033[91m"
	BRIGHT_GREEN = "\033[92m"
	BRIGHT_YELLOW = "\033[93m"
	BRIGHT_BLUE = "\033[94m"
	BRIGHT_PURPLE = "\033[95m"
	BRIGHT_CYAN = "\033[96m"
	BRIGHT_WHITE = "\033[97m"

	RESET = "\033[0m"

class Background:
	BG_BLACK = "\033[40m"
	BG_RED = "\033[41m"
	BG_GREEN = "\033[42m"
	BG_YELLOW = "\033[43m"
	BG_BLUE = "\033[44m"
	BG_PURPLE = "\033[45m"
	BG_CYAN = "\033[46m"
	BG_WHITE = "\033[47m"

	# fundos brilhantes
	BG_BRIGHT_RED = "\033[101m"
	BG_BRIGHT_GREEN = "\033[102m"
	BG_BRIGHT_YELLOW = "\033[103m"
	BG_BRIGHT_BLUE = "\033[104m"
	BG_BRIGHT_PURPLE = "\033[105m"
	BG_BRIGHT_CYAN = "\033[106m"
	BG_BRIGHT_WHITE = "\033[107m"

class Style:
	BOLD = "\033[1m"
	DIM = "\033[2m"
	ITALIC = "\033[3m"
	UNDERLINE = "\033[4m"
	RESET = "\033[0m"

# EXEMPLOS: 
# print(Style.BOLD + Color.RED + "ERRO" + Color.RESET)
# print(Color.GREEN + "Texto verde" + Color.RESET)
#
# print(Color.BRIGHT_RED + "Erro crítico" + Color.RESET)
#
# print(Background.BG_BLUE + Color.WHITE + "Texto com fundo azul" + Color.RESET)
#
# print(Style.BOLD + Color.BRIGHT_CYAN + "Texto neon" + Color.RESET)

BANNER = f"""╔════════════════════════════════════════════════════════╗
║ {Color.RED}▄▄▄▄  ▄▄  ▄▄  ▄▄▄▄ ▄▄     ▄▄▄   ▄▄▄  ▄▄ ▄▄ ▄▄ ▄▄ ▄▄▄▄{Color.RESET}  ║
║ {Color.RED}██▀██ ███▄██ ███▄▄ ██    ██▀██ ██▀██ ██▄█▀ ██ ██ ██▄█▀{Color.RESET} ║
║ {Color.RED}████▀ ██ ▀██ ▄▄██▀ ██▄▄▄ ▀███▀ ▀███▀ ██ ██ ▀███▀ ██{Color.RESET}    ║
║                                                        ║
║ {Background.BG_BRIGHT_RED + Color.WHITE + Style.BOLD}  Guilherme Alexander | DNSLookUp Tool v2.0 [Python 3.12]      {Color.RESET} ║                      
╚════════════════════════════════════════════════════════╝
"""

def lookup(domain, record):
	try:
		answers = dns.resolver.resolve(domain, record)

		print(f"\n{Color.GREEN + Style.BOLD }[+] {record} records: {Color.RESET}")

		for rdata in answers:
			print(rdata)
	except:
		print(f"{Background.BG_RED + Color.WHITE}[-] {record} não encontrado {Color.RESET}")


def main():
	parser = argparse.ArgumentParser(
		description="DNSLookup Tool", 
		epilog="Exemplo: python dnslookup.py google.com --mx --ns"
	)

	parser.add_argument("domain", help="Domínio Alvo")
	
	parser.add_argument("-all", "--all", action="store_true", help="Buscar registro A AAAA MX NS TXT")

	parser.add_argument("-a", "--a", action="store_true", help="Buscar registro A")
	parser.add_argument("-mx", "--mx", action="store_true", help="Buscar registro MX")
	parser.add_argument("-ns", "--ns", action="store_true", help="Buscar registro NS")
	parser.add_argument("-txt", "--txt", action="store_true", help="Buscar registro TXT")
	parser.add_argument("-aaaa","--aaaa", action="store_true", help="Buscar registro IPv6")

	args = parser.parse_args()

	domain = args.domain

	print(f"\n{Background.BG_BLUE + Color.WHITE}[!] [DNSLookup - {domain}]{Color.RESET}")

	if args.all:
		lookup(domain, "A")
		lookup(domain, "AAAA")
		lookup(domain, "MX")
		lookup(domain, "NS")
		lookup(domain, "TXT")

	if args.a:
		lookup(domain, "A")

	if args.mx:
		lookup(domain, "MX")

	if args.ns:
		lookup(domain, "NS")

	if args.txt:
		lookup(domain, "TXT")

	if args.aaaa:
		lookup(domain, "AAAA")

if __name__ == "__main__":
	print(f"{BANNER}")
	main()

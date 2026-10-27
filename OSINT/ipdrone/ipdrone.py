#!/usr/bin/env python3
####################################################################
#
# Guilherme-alexander
# https://github.com/Guilherme-alexander
#
# ipdrone-osint.py — Ferramenta OSINT para IP / Domínio
# Uso educacional e para OSINT autorizado apenas.
#
####################################################################
# Requer: pip install requests dnspython
####################################################################
# Fazer tudo (IP + DNS + RDAP) num alvo
# python ipdrone-osint.py 8.8.8.8
# python ipdrone-osint.py github.com
####################################################################
# Apenas geolocalização por IP
# python ipdrone-osint.py github.com --ip
####################################################################
# Apenas DNS
# python ipdrone-osint.py github.com --dns
####################################################################
# Apenas WHOIS (via RDAP)
# python ipdrone-osint.py github.com --whois
####################################################################
# Apenas RDAP detalhado (JSON bruto)
# python ipdrone-osint.py 8.8.8.8 --rdap
####################################################################
# Salvar em JSON ou TXT
# python ipdrone-osint.py github.com --save resultado.json
# python ipdrone-osint.py 8.8.8.8 --save info.txt
####################################################################
# Sem banner (para pipelines)
# python ipdrone-osint.py 1.1.1.1 --no-banner --json
####################################################################


import argparse
import ipaddress
import json
import logging
import socket
import sys
import time
from dataclasses import dataclass, asdict, field
from io import StringIO
from pathlib import Path
from typing import Optional

import requests
from dns import resolver, reversename

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
CACHE_FILE = Path.home() / ".cache" / "ipdrone_osint.json"
CACHE_TTL = 3600
REQUEST_TIMEOUT = 10
USER_AGENT = "ipdrone-osint/3.1 (educational OSINT tool)"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ipdrone")

# ---------------------------------------------------------------------------
# ANSI escape codes — formatação nativa de terminal (sem dependências)
# ---------------------------------------------------------------------------
RESET = "\033[0m"

# Foreground — 30-37 normais, 90-97 brilhantes
BLACK   = "\033[30m"
RED     = "\033[31m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
BLUE    = "\033[34m"
PURPLE  = "\033[35m"   # magenta
CYAN    = "\033[36m"
WHITE   = "\033[37m"
GRAY    = "\033[90m"   # cinza (bright black)

BRIGHT_RED     = "\033[91m"
BRIGHT_GREEN   = "\033[92m"
BRIGHT_YELLOW  = "\033[93m"
BRIGHT_BLUE    = "\033[94m"
BRIGHT_PURPLE  = "\033[95m"
BRIGHT_CYAN    = "\033[96m"
BRIGHT_WHITE   = "\033[97m"

# Background — 40-47 normais, 100-107 brilhantes
BACKGROUND_BLACK   = "\033[40m"
BACKGROUND_RED     = "\033[41m"
BACKGROUND_GREEN   = "\033[42m"
BACKGROUND_YELLOW  = "\033[43m"
BACKGROUND_BLUE    = "\033[44m"
BACKGROUND_PURPLE  = "\033[45m"
BACKGROUND_CYAN    = "\033[46m"
BACKGROUND_WHITE   = "\033[47m"

BACKGROUND_BRIGHT_BLACK  = "\033[100m"
BACKGROUND_BRIGHT_RED    = "\033[101m"
BACKGROUND_BRIGHT_GREEN  = "\033[102m"
BACKGROUND_BRIGHT_YELLOW = "\033[103m"
BACKGROUND_BRIGHT_BLUE   = "\033[104m"
BACKGROUND_BRIGHT_PURPLE = "\033[105m"
BACKGROUND_BRIGHT_CYAN   = "\033[106m"
BACKGROUND_BRIGHT_WHITE  = "\033[107m"

# Estilos
BOLD      = "\033[1m"
DIM       = "\033[2m"
ITALIC    = "\033[3m"
UNDERLINE = "\033[4m"
BLINK     = "\033[5m"
REVERSE   = "\033[7m"
HIDDEN    = "\033[8m"
STRIKE    = "\033[9m"


# ---------------------------------------------------------------------------
# Detecção de TTY — desliga cores quando a saída não é terminal (pipes, .txt)
# ---------------------------------------------------------------------------
_COLOR_STDOUT: Optional[bool] = None


def _should_color() -> bool:
    """True apenas se stdout E stderr forem TTYs. Cacheado."""
    global _COLOR_STDOUT
    if _COLOR_STDOUT is None:
        try:
            _COLOR_STDOUT = sys.stdout.isatty() and sys.stderr.isatty()
        except (AttributeError, ValueError):
            _COLOR_STDOUT = False
    return _COLOR_STDOUT


def colorize(text: str, *styles: str) -> str:
    """Aplica múltiplos estilos e reseta ao final. No-op se não for TTY."""
    if not _should_color() or not styles:
        return text
    return "".join(styles) + text + RESET


# ---------------------------------------------------------------------------
# Helpers de log colorido
# ---------------------------------------------------------------------------
def log_info(msg: str, *args) -> None:
    log.info(colorize(msg, CYAN) if _should_color() else msg, *args)


def log_warn(msg: str, *args) -> None:
    log.warning(colorize(msg, YELLOW) if _should_color() else msg, *args)


def log_err(msg: str, *args) -> None:
    log.error(colorize(msg, BOLD, RED) if _should_color() else msg, *args)


def log_ok(msg: str, *args) -> None:
    log.info(colorize(msg, BOLD, GREEN) if _should_color() else msg, *args)


# ---------------------------------------------------------------------------
# Banner Home
# ---------------------------------------------------------------------------
BANNER = r"""  _  ____  ____  ____   ___  _   _ _____
 (_)|  _ \|  _ \|  _ \ / _ \| \ | | ____|
 | || |_) | |_) | | | | | | |  \| |  _|
 | ||  __/|  _ <| |_| | |_| | |\  | |___
 |_||_|   |_| \_\____/ \___/|_| \_|_____|
        OSINT IP / Domain Tool v3.1
     Uso educacional e OSINT autorizado

 Author: Guilherme-alexander
 Github: https://github.com/Guilherme-alexander
"""


# ---------------------------------------------------------------------------
# Modelo de dados
# ---------------------------------------------------------------------------
@dataclass
class IPInfo:
    query: str = ""
    resolved_ip: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    postal: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    source: Optional[str] = None
    error: Optional[str] = None
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------
def _load_cache() -> dict:
    if not CACHE_FILE.exists():
        return {}
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache: dict) -> None:
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except OSError as e:
        log_warn("Não foi possível salvar cache: %s", e)


def _cache_get(key: str) -> Optional[dict]:
    cache = _load_cache()
    entry = cache.get(key)
    if not entry:
        return None
    if time.time() - entry.get("_ts", 0) > CACHE_TTL:
        return None
    return entry.get("data")


def _cache_set(key: str, data: dict) -> None:
    cache = _load_cache()
    cache[key] = {"_ts": time.time(), "data": data}
    _save_cache(cache)


# ---------------------------------------------------------------------------
# Resolução de alvo
# ---------------------------------------------------------------------------
def resolve_target(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None)
        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET:
                return sockaddr[0]
        return infos[0][4][0]
    except socket.gaierror as e:
        raise ValueError(f"Não foi possível resolver '{target}': {e}") from e


# ---------------------------------------------------------------------------
# Provedores de geolocalização por IP (HTTPS)
# ---------------------------------------------------------------------------
def _request(url: str, headers: Optional[dict] = None) -> dict:
    h = {"User-Agent": USER_AGENT}
    if headers:
        h.update(headers)
    r = requests.get(url, timeout=REQUEST_TIMEOUT, headers=h)
    r.raise_for_status()
    return r.json()


def provider_ipwhois(ip: str) -> IPInfo:
    data = _request(f"https://ipwho.is/{ip}")
    if not data.get("success", True):
        raise ValueError(data.get("message", "ipwho.is falhou"))
    conn = data.get("connection", {})
    return IPInfo(
        query=ip,
        isp=conn.get("isp"),
        org=conn.get("org"),
        asn=f"AS{conn['asn']}" if conn.get("asn") else None,
        city=data.get("city"),
        region=data.get("region"),
        country=data.get("country"),
        country_code=data.get("country_code"),
        postal=data.get("postal"),
        latitude=data.get("latitude"),
        longitude=data.get("longitude"),
        timezone=data.get("timezone", {}).get("id"),
        source="ipwho.is",
    )


def provider_ipapi_co(ip: str) -> IPInfo:
    data = _request(f"https://ipapi.co/{ip}/json/")
    if data.get("error"):
        raise ValueError(data.get("reason", "ipapi.co falhou"))
    return IPInfo(
        query=ip,
        isp=data.get("org"),
        org=data.get("org"),
        asn=data.get("asn"),
        city=data.get("city"),
        region=data.get("region"),
        country=data.get("country_name"),
        country_code=data.get("country_code"),
        postal=data.get("postal"),
        latitude=data.get("latitude"),
        longitude=data.get("longitude"),
        timezone=data.get("timezone"),
        source="ipapi.co",
    )


PROVIDERS = [provider_ipwhois, provider_ipapi_co]


def lookup_ip(target: str, use_cache: bool = True) -> IPInfo:
    try:
        ip = resolve_target(target)
    except ValueError as e:
        return IPInfo(query=target, error=str(e))

    cache_key = f"ip:{ip}"
    if use_cache:
        cached = _cache_get(cache_key)
        if cached:
            log_ok("Cache hit para %s", ip)
            return IPInfo(**cached)

    last_error = None
    for provider in PROVIDERS:
        try:
            log_info("Consultando %s via %s ...", ip, provider.__name__)
            info = provider(ip)
            info.resolved_ip = ip if ip != target else None
            info.query = target
            if use_cache:
                _cache_set(cache_key, asdict(info))
            return info
        except (requests.RequestException, ValueError, KeyError) as e:
            last_error = e
            log_warn("%s falhou: %s", provider.__name__, e)
            time.sleep(0.5)
    return IPInfo(query=target, resolved_ip=ip, error=f"Todos os provedores falharam: {last_error}")


# ---------------------------------------------------------------------------
# DNS (dnspython)
# ---------------------------------------------------------------------------
def lookup_dns(target: str) -> dict:
    """Consulta registros DNS comuns. Retorna dict com resultados/erros."""
    result = {"target": target, "records": {}, "errors": {}}
    record_types = ["A", "AAAA", "MX", "NS", "TXT"]

    for rtype in record_types:
        try:
            answers = resolver.resolve(target, rtype, lifetime=REQUEST_TIMEOUT)
            result["records"][rtype] = [str(r) for r in answers]
        except (resolver.NoAnswer, resolver.NXDOMAIN, resolver.Timeout, resolver.NoNameservers) as e:
            result["errors"][rtype] = str(e)
        except Exception as e:
            result["errors"][rtype] = str(e)

    # Reverse DNS (PTR) se for IP
    try:
        ipaddress.ip_address(target)
        rev = reversename.from_address(target)
        ptr = resolver.resolve(rev, "PTR", lifetime=REQUEST_TIMEOUT)
        result["records"]["PTR"] = [str(r) for r in ptr]
    except (ValueError, resolver.NoAnswer, resolver.NXDOMAIN, resolver.Timeout, Exception):
        pass

    return result


# ---------------------------------------------------------------------------
# RDAP (WHOIS moderno via rdap.org)
# ---------------------------------------------------------------------------
def lookup_rdap(target: str) -> dict:
    """Consulta RDAP via bootstrap server rdap.org. Retorna JSON bruto + resumo."""
    try:
        ipaddress.ip_address(target)
        rdap_type = "ip"
        rdap_object = target
    except ValueError:
        rdap_type = "domain"
        rdap_object = target

    url = f"https://rdap.org/{rdap_type}/{rdap_object}"
    log_info("RDAP: %s", url)

    try:
        r = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"},
        )
        r.raise_for_status()
        data = r.json()
        return {
            "target": target,
            "type": rdap_type,
            "source": "rdap.org",
            "status_code": r.status_code,
            "data": data,
        }
    except requests.RequestException as e:
        return {"target": target, "type": rdap_type, "error": str(e)}
    except json.JSONDecodeError as e:
        return {"target": target, "type": rdap_type, "error": f"JSON inválido: {e}"}


# ---------------------------------------------------------------------------
# Saída — funções recebem out=sys.stdout para permitir captura limpa
# ---------------------------------------------------------------------------
def print_ip_info(info: IPInfo, out=sys.stdout) -> None:
    if info.error:
        print(colorize(f"[ERRO IP] {info.error}", BOLD, RED), file=out)
        return
    fields = [
        ("Alvo", info.query),
        ("IP resolvido", info.resolved_ip),
        ("ISP", info.isp),
        ("Organização", info.org),
        ("ASN", info.asn),
        ("Cidade", info.city),
        ("Região", info.region),
        ("País", f"{info.country} ({info.country_code})" if info.country else None),
        ("CEP", info.postal),
        ("Latitude", info.latitude),
        ("Longitude", info.longitude),
        ("Fuso horário", info.timezone),
        ("Fonte", info.source),
    ]
    width = max(len(k) for k, _ in fields)
    for key, value in fields:
        if value not in (None, ""):
            # padding aplicado ANTES do colorize — alinhamento preservado
            label = colorize(f"{key:<{width}}", BOLD, RED)
            print(f"  {label} : {value}", file=out)


def print_dns_result(dns: dict, out=sys.stdout) -> None:
    print(colorize(f"\n[DNS] Alvo: {dns['target']}", BOLD, GREEN), file=out)
    for rtype, values in dns.get("records", {}).items():
        print(f"  {colorize(rtype, BOLD, YELLOW)}:", file=out)
        for v in values:
            print(f"    - {v}", file=out)
    for rtype, err in dns.get("errors", {}).items():
        log.debug("DNS %s: %s", rtype, err)


def print_rdap_result(rdap: dict, out=sys.stdout) -> None:
    header = f"\n[RDAP] Alvo: {rdap.get('target')} (tipo: {rdap.get('type')})"
    print(colorize(header, BOLD, GREEN), file=out)
    if rdap.get("error"):
        print(colorize(f"  [ERRO] {rdap['error']}", BOLD, RED), file=out)
        return

    data = rdap.get("data", {})
    print(f"  {colorize('Fonte', BOLD)}: {rdap.get('source')}")
    if data.get("handle"):
        print(f"  {colorize('Handle', BOLD)}: {data['handle']}")
    if data.get("name"):
        print(f"  {colorize('Nome', BOLD)}: {data['name']}")
    if data.get("startAddress") and data.get("endAddress"):
        print(f"  {colorize('Range', BOLD)}: {data['startAddress']} - {data['endAddress']}")
    if data.get("status"):
        status = ", ".join(data["status"]) if isinstance(data["status"], list) else data["status"]
        print(f"  {colorize('Status', BOLD)}: {status}")

    entities = data.get("entities", [])
    if entities:
        print(f"  {colorize('Entidades', BOLD)}:")
        for ent in entities[:5]:
            roles = ", ".join(ent.get("roles", [])) if ent.get("roles") else "?"
            handle = ent.get("handle", "?")
            print(f"    - {handle} ({roles})")

    events = data.get("events", [])
    if events:
        print(f"  {colorize('Eventos', BOLD)}:")
        for ev in events:
            print(f"    - {ev.get('eventAction', '?')}: {ev.get('eventDate', '?')}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ipdrone-osint",
        description="OSINT para IP/domínio: geolocalização, DNS e RDAP (WHOIS moderno).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", help="Endereço IP (v4/v6) ou domínio alvo")
    p.add_argument("--ip", action="store_true", help="Consulta de geolocalização/ISP via IP")
    p.add_argument("--dns", action="store_true", help="Consulta registros DNS (A, AAAA, MX, NS, TXT, PTR)")
    p.add_argument("--whois", action="store_true", help="Consulta WHOIS via RDAP (rdap.org)")
    p.add_argument("--rdap", action="store_true", help="Consulta RDAP detalhada (JSON bruto)")
    p.add_argument("-j", "--json", action="store_true", help="Saída em JSON")
    p.add_argument("-o", "--save", metavar="ARQUIVO", help="Salvar saída em .json ou .txt")
    p.add_argument("--no-cache", action="store_true", help="Ignorar cache de IP")
    p.add_argument("-q", "--quiet", action="store_true", help="Silenciar logs")
    p.add_argument("--banner", action="store_true", default=True, help="Exibir banner (padrão: True)")
    p.add_argument("--no-banner", action="store_false", dest="banner", help="Ocultar banner")
    return p


def _render_txt(results: dict) -> str:
    """Renderiza o relatório em texto puro (sem ANSI), capturando via StringIO."""
    buf = StringIO()
    if "ip" in results:
        info = IPInfo(**results["ip"])
        print_ip_info(info, out=buf)
    if "dns" in results:
        print_dns_result(results["dns"], out=buf)
    if "rdap" in results:
        print_rdap_result(results["rdap"], out=buf)
    return buf.getvalue()


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.banner:
        # Banner só no stderr para não poluir --json / --save
        print(colorize(BANNER, BOLD, GRAY), file=sys.stderr)

    if args.quiet:
        log.setLevel(logging.ERROR)

    if not args.target:
        parser.print_help()
        return 1

    target = args.target
    results = {"target": target}
    exit_code = 0

    run_all = not any([args.ip, args.dns, args.whois, args.rdap])

    if args.ip or run_all:
        info = lookup_ip(target, use_cache=not args.no_cache)
        results["ip"] = asdict(info)
        if info.error:
            exit_code = 1
        if not args.json:
            print_ip_info(info)

    if args.dns or run_all:
        dns = lookup_dns(target)
        results["dns"] = dns
        if not args.json:
            print_dns_result(dns)

    if args.whois or args.rdap or run_all:
        rdap = lookup_rdap(target)
        results["rdap"] = rdap
        if rdap.get("error"):
            exit_code = 1
        if not args.json:
            print_rdap_result(rdap)

    # JSON para stdout (pipe-friendly)
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False, default=str))

    # Save — JSON estruturado ou TXT limpo (sem ANSI)
    if args.save:
        save_path = Path(args.save)
        try:
            if save_path.suffix.lower() == ".json":
                save_path.write_text(
                    json.dumps(results, indent=2, ensure_ascii=False, default=str),
                    encoding="utf-8",
                )
            else:
                save_path.write_text(_render_txt(results), encoding="utf-8")
            log_ok("Salvo em %s", save_path)
        except OSError as e:
            log_err("Falha ao salvar %s: %s", save_path, e)
            exit_code = 1

    return exit_code


if __name__ == "__main__":
    sys.exit(main())

# ipdrone

> Ferramenta OSINT de linha de comando para consulta de **IP**, **DNS** e **RDAP (WHOIS moderno)** — em Python puro, sem dependências pesadas.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-estável-brightgreen)
![Uso](https://img.shields.io/badge/uso-educacional%20%2F%20OSINT%20autorizado-orange)

---

## 📌 Sobre

`ipdrone` é um script de linha de comando para **OSINT autorizado** que reúne, em uma única execução:

- **Geolocalização aproximada por IP** (ISP, ASN, cidade, país, coordenadas, fuso)
- **Consulta DNS** (A, AAAA, MX, NS, TXT e PTR/reverse)
- **RDAP** — o substituto moderno e estruturado do WHOIS clássico
- **Saída colorida** no terminal (ANSI nativo, sem bibliotecas)
- **Saída em JSON** para pipelines (`jq`, scripts, SIEM)
- **Exportação** para `.json` ou `.txt` limpo (sem códigos ANSI)
- **Cache local** com TTL para evitar requisições repetidas
- **Fallback entre provedores** de geolocalização

> ⚠️ **Este projeto é destinado a fins educacionais e a OSINT autorizado** (pentest contratado, bug bounty, pesquisa acadêmica, due diligence). Consultar IPs de terceiros sem autorização pode violar a LGPD/GDPR e legislações locais.

---

## 🚀 Instalação

### Requisitos

- Python **3.8+**
- `pip`

### Dependências

```bash
pip install requests dnspython
```

### Clonando o repositório

```bash
git clone https://github.com/<seu-usuario>/ipdrone.git
cd ipdrone
```

### (Opcional) Ambiente virtual

```bash
python3 -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows
pip install requests dnspython
```

---

## 🧭 Uso

```bash
python ipdrone.py <alvo> [opções]
```

O `<alvo>` pode ser:

- IPv4 (`8.8.8.8`)
- IPv6 (`2606:4700:4700::1111`) Cloudflare 
- Domínio (`github.com`) — será resolvido via DNS

### Opções

| Flag | Descrição |
|------|-----------|
| `--ip` | Consulta apenas geolocalização/ISP via IP |
| `--dns` | Consulta apenas registros DNS (A, AAAA, MX, NS, TXT, PTR) |
| `--whois` | Consulta WHOIS via RDAP (`rdap.org`) |
| `--rdap` | Consulta RDAP detalhada (JSON bruto) |
| `-j`, `--json` | Saída em JSON (pipe-friendly) |
| `-o`, `--save ARQUIVO` | Salva a saída em `.json` ou `.txt` |
| `--no-cache` | Ignora o cache local de IP |
| `-q`, `--quiet` | Silencia logs |
| `--no-banner` | Oculta o banner (útil em pipelines) |
| `-h`, `--help` | Ajuda |

> 💡 Se **nenhuma** das flags `--ip`, `--dns`, `--whois` ou `--rdap` for passada, a ferramenta executa **todas** as consultas.

---

## 📖 Exemplos

### Fazer tudo (IP + DNS + RDAP)

```bash
python ipdrone.py 8.8.8.8
python ipdrone.py github.com
```

### Apenas geolocalização por IP

```bash
python ipdrone.py github.com --ip
```

### Apenas DNS

```bash
python ipdrone.py github.com --dns
```

### Apenas WHOIS (via RDAP)

```bash
python ipdrone.py github.com --whois
```

### Apenas RDAP detalhado (JSON bruto)

```bash
python ipdrone.py 8.8.8.8 --rdap
```

### Salvar em JSON

```bash
python ipdrone.py github.com --save resultado.json
```

### Salvar em TXT (limpo, sem ANSI)

```bash
python ipdrone.py 8.8.8.8 --save info.txt
```

### Pipeline com `jq` (sem banner, JSON puro)

```bash
python ipdrone.py 1.1.1.1 --no-banner --json | jq '.ip.isp, .ip.country'
```

### Consultar vários alvos em loop

```bash
for ip in 8.8.8.8 1.1.1.1 9.9.9.9; do
  python ipdrone.py "$ip" --ip --no-banner --json >> resultados.jsonl
done
```

---

## 🖥️ Saída

### Terminal (colorido)

```
  _  ____  ____  ____   ___  _   _ _____
 (_)|  _ \|  _ \|  _ \ / _ \| \ | | ____|
 | || |_) | |_) | | | | | | |  \| |  _|
 | ||  __/|  _ <| |_| | |_| | |\  | |___
 |_||_|   |_| \_\____/ \___/|_| \_|_____|
        OSINT IP / Domain Tool v3.1
     Uso educacional e OSINT autorizado

  Alvo          : github.com
  IP resolvido  : 140.82.112.3
  ISP           : GitHub, Inc.
  Organização   : GitHub, Inc.
  ASN           : AS36459
  Cidade        : San Francisco
  Região        : California
  País          : United States (US)
  CEP           : 94107
  Latitude      : 37.7749
  Longitude     : -122.4194
  Fuso horário  : America/Los_Angeles
  Fonte         : ipwho.is

[DNS] Alvo: github.com
  A:
    - 140.82.112.3
  AAAA:
    - 2606:50c0:8000::153
  MX:
    - 10 alt1.aspmx.l.google.com.
  ...

[RDAP] Alvo: github.com (tipo: domain)
  Fonte: rdap.org
  Handle: GITHUB-1
  Nome: GitHub, Inc.
  Status: client transfer prohibited
  Entidades:
    - GITHUB-1 (registrant)
  Eventos:
    - registration: 2007-10-09T18:20:50Z
    - expiration: 2025-10-09T18:20:50Z
```

### JSON

```json
{
  "target": "github.com",
  "ip": {
    "query": "github.com",
    "resolved_ip": "140.82.112.3",
    "isp": "GitHub, Inc.",
    "org": "GitHub, Inc.",
    "asn": "AS36459",
    "city": "San Francisco",
    "region": "California",
    "country": "United States",
    "country_code": "US",
    "postal": "94107",
    "latitude": 37.7749,
    "longitude": -122.4194,
    "timezone": "America/Los_Angeles",
    "source": "ipwho.is",
    "error": null
  },
  "dns": {
    "target": "github.com",
    "records": { "A": ["140.82.112.3"], "MX": ["10 alt1.aspmx.l.google.com."] },
    "errors": {}
  },
  "rdap": {
    "target": "github.com",
    "type": "domain",
    "source": "rdap.org",
    "status_code": 200,
    "data": { "...": "..." }
  }
}
```

---

## ⚙️ Como funciona

| Etapa | Tecnologia |
|-------|------------|
| Resolução do alvo | `ipaddress` + `socket.getaddrinfo` |
| Geolocalização | APIs públicas HTTPS: [`ipwho.is`](https://ipwho.is), [`ipapi.co`](https://ipapi.co) (fallback) |
| DNS | [`dnspython`](https://www.dnspython.org/) |
| WHOIS moderno | [RDAP via `rdap.org`](https://rdap.org) (bootstrap server) |
| Cache | JSON em `~/.cache/ipdrone_osint.json` (TTL 1h) |
| Cores | Escape codes ANSI nativos (sem `colorama`) |

### Por que RDAP em vez de WHOIS?

O WHOIS clássico (porta 43) é um protocolo legado, sem criptografia, sem formato padronizado e em processo de descontinuação. O **RDAP** (Registration Data Access Protocol) é o substituto oficial: usa **HTTPS**, retorna **JSON estruturado** e é mantido pelos RIRs (ARIN, RIPE, APNIC, LACNIC, AFRINIC). Por isso o comando `--whois` foi implementado como alias para `--rdap`.

---

## ⚠️ Limitações (leia antes de usar)

1. **Geolocalização por IP é aproximada** — geralmente só chega ao nível de cidade. Nunca será "endereço exato".
2. **VPN/proxy/Tor tornam o resultado inútil** — o IP mostrado será do servidor de saída.
3. **APIs gratuitas têm rate limit**:
   - `ipwho.is`: ~10.000 req/mês
   - `ipapi.co`: ~1.000 req/dia
   - `rdap.org`: ~10 req / 10s por IP
4. **RDAP depende do TLD** — alguns registros têm cobertura parcial. Para WHOIS clássico de TLDs específicos, use `python-whois` como complemento.
5. **Cache local** — para forçar consulta nova, use `--no-cache`.
6. **Cores desligadas automaticamente** em pipes, redirecionamentos e arquivos (detecção de TTY).

Para OSINT sério, combine esta ferramenta com:

- **WHOIS/RDAP direto** no RIR correspondente
- **Certificate Transparency** (`crt.sh`)
- **Shodan / Censys** (portas e serviços)
- **DNS history** (SecurityTrails, ViewDNS)
- **Reverse IP** (YouGetSignal, HackerTarget)

---

## 🤝 Contribuindo

1. Faça um fork
2. Crie uma branch: `git checkout -b feature/minha-feature`
3. Commit: `git commit -m "feat: minha feature"`
4. Push: `git push origin feature/minha-feature`
5. Abra um Pull Request

### Ideias de contribuição

- Suporte a WHOIS clássico via `python-whois` como fallback
- Integração com Shodan / Censys
- Consulta a Certificate Transparency (`crt.sh`)
- Saída em CSV
- Testes unitários (`pytest`)
- Suporte a múltiplos alvos via arquivo (`--file targets.txt`)

---

## 📄 Licença

Distribuído sob a licença **MIT**. Veja [`LICENSE`](LICENSE) para mais detalhes.

---

## ⚖️ Aviso legal

Esta ferramenta é fornecida **apenas para fins educacionais e para OSINT autorizado**. O autor não se responsabiliza por uso indevido, incluindo — mas não se limitando a — rastreamento de pessoas sem consentimento, violação de privacidade, ou qualquer atividade que viole a **LGPD (Lei 13.709/2018)**, o **GDPR (Regulamento UE 2016/679)** ou legislações equivalentes.

**Use com responsabilidade. Consulte apenas alvos que você tem autorização para investigar.**

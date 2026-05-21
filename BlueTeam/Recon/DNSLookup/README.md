# DNSLookup

> Simple DNS enumeration tool written in Python.

## Overview

DNSLookup is a lightweight command-line DNS enumeration utility built with Python and dnspython.

The tool allows quick retrieval of common DNS records including:

- A
- AAAA
- MX
- NS
- TXT

Useful for:

- infrastructure analysis
- troubleshooting
- OSINT
- blue team investigations
- recon workflows

---

## Features

- Colored terminal output
- Fast DNS queries
- Multiple record support
- Bulk lookup mode
- Simple CLI interface
- Lightweight and dependency minimal

---

## Supported Records

| Record | Description |
|---|---|
| A | IPv4 address |
| AAAA | IPv6 address |
| MX | Mail servers |
| NS | Name servers |
| TXT | TXT/SPF/verification records |

---

## Installation

<details>
<summary>Install dependencies</summary>

```bash
pip install dnspython
```

</details>

---

## Usage

### Query all records

```bash
python dnslookup.py google.com --all
```

### Query A record

```bash
python dnslookup.py google.com --a
```

### Query MX records

```bash
python dnslookup.py google.com --mx
```

### Query NS records

```bash
python dnslookup.py google.com --ns
```

### Query TXT records

```bash
python dnslookup.py google.com --txt
```

### Query AAAA records

```bash
python dnslookup.py google.com --aaaa
```

---

## Example Output

```text
[+] MX records:

smtp.google.com
alt1.gmail-smtp-in.l.google.com
```

---

## Repository Structure

```text
BlueTeam/
└── Recon/
    └── DNSLookup/
        ├── dnslookup.py
        ├── README.md
        └── requirements.txt
```

---

## Future Improvements

- CNAME support
- SOA lookup
- DNSSEC checks
- Reverse DNS lookup
- JSON output
- Multi-threaded queries
- Subdomain enumeration

---

## Dependencies

- Python 3.10+
- dnspython

---

## Educational Purpose

This project is intended for:

- DNS learning
- infrastructure analysis
- defensive security research
- OSINT workflows
- networking education

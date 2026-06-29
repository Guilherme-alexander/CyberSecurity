# DDoS (Distributed Denial of Service)

## 📌 Definição

DDoS (Distributed Denial of Service) é um ataque cibernético que visa tornar um serviço, servidor ou infraestrutura de rede indisponível para seus usuários legítimos. O ataque é realizado através do envio massivo de tráfego malicioso de múltiplas fontes comprometidas (botnets), sobrecarregando os recursos do alvo até que ele não consiga mais atender requisições válidas.

---

## 🧠 Como Funciona

O ataque DDoS segue estas etapas:

1. **Recrutamento**: O atacante infecta dispositivos (computadores, IoT, servidores) com malware, formando uma **botnet**.
2. **Comando e Controle (C&C)**: Os dispositivos infectados aguardam instruções de um servidor de comando.
3. **Ataque**: O atacante envia o comando para todos os dispositivos da botnet atacarem simultaneamente o alvo.
4. **Sobrecarga**: O tráfego excessivo consome largura de banda, CPU, memória ou conexões do servidor alvo.
5. **Indisponibilidade**: O serviço fica lento ou totalmente inacessível para usuários legítimos.

---

## 🧩 Tipos de Ataques DDoS

### 1. **Ataques de Volume (Volumetric)**
Sobrecarregam a largura de banda da rede com tráfego massivo.

| Subtipo | Descrição |
|---------|-----------|
| **UDP Flood** | Envia pacotes UDP falsificados para portas aleatórias. |
| **ICMP Flood (Ping Flood)** | Inunda o alvo com pacotes ICMP Echo Request. |
| **Amplification Attacks** | Explora servidores vulneráveis para amplificar o tráfego (ex: DNS Amplification, NTP Amplification). |

### 2. **Ataques de Protocolo (Protocol)**
Exploram vulnerabilidades em protocolos de rede.

| Subtipo | Descrição |
|---------|-----------|
| **SYN Flood** | Envia requisições SYN sem completar o handshake TCP, esgotando conexões. |
| **ACK Flood** | Inunda com pacotes ACK, sobrecarregando firewalls e balanceadores. |
| **Ping of Death** | Envia pacotes ICMP maiores que o permitido, causando crash. |

### 3. **Ataques de Camada de Aplicação (Application Layer)**
Atacam vulnerabilidades em aplicações web e serviços.

| Subtipo | Descrição |
|---------|-----------|
| **HTTP Flood** | Envia requisições HTTP GET/POST massivas. |
| **Slowloris** | Mantém conexões HTTP abertas por longos períodos. |
| **Slow POST** | Envia dados HTTP POST muito lentamente, esgotando recursos. |
| **RUDY (R-U-Dead-Yet)** | Envia formulários com campos longos para travar a aplicação. |

---

## 🎯 Alvos Comuns

- Sites de e-commerce
- Instituições financeiras
- Provedores de serviços (SaaS, cloud)
- Infraestrutura governamental
- Servidores de jogos online
- Plataformas de mídia social

---

## 🛡️ Como se Proteger

### Medidas Preventivas

- ✅ **Balanceamento de Carga**: Distribuir tráfego entre múltiplos servidores.
- ✅ **Escalabilidade Automática**: Aumentar recursos dinamicamente sob demanda.
- ✅ **CDN (Content Delivery Network)**: Absorver e distribuir tráfego globalmente.
- ✅ **Firewalls de Aplicação Web (WAF)**: Filtrar tráfego malicioso.
- ✅ **Rate Limiting**: Limitar número de requisições por IP.
- ✅ **Anycast Network**: Espalhar tráfego por múltiplos data centers.

### Detecção e Resposta

- ✅ **Monitoramento em Tempo Real**: Ferramentas de análise de tráfego.
- ✅ **Sistemas de Detecção de Intrusão (IDS/IPS)**.
- ✅ **Planos de Resposta a Incidentes**: Procedimentos pré-definidos.
- ✅ **Parceria com Provedores Anti-DDoS**: Serviços especializados em mitigação.

---

## 🧰 Ferramentas de Mitigação

| Ferramenta | Tipo | Descrição |
|------------|------|-----------|
| **Cloudflare** | CDN + Anti-DDoS | Proteção em camada de rede e aplicação. |
| **AWS Shield** | Gerenciado | Proteção para infraestrutura AWS. |
| **Akamai Prolexic** | Especializado | Mitigação em escala de provedor. |
| **Imperva DDoS** | WAF + DDoS | Proteção de aplicações web. |
| **Fastly** | CDN | Proteção com Anycast e rate limiting. |
| **Arbor Networks** | On-premise | Detecção e mitigação para ISPs e data centers. |

---

## 📘 Exemplo Prático

**Cenário de Ataque SYN Flood:**

```bash
# Comando simplificado para simular (apenas educacional)
hping3 -S -p 80 --flood --rand-source alvo.com
```

**Impacto:**
- Servidor recebe milhares de requisições SYN por segundo.
- Tabela de conexões (backlog) se esgota.
- Conexões legítimas são recusadas (SYN-ACK nunca completa).
- Servidor fica inacessível.

**Mitigação:**
- **SYN Cookies**: Técnica que verifica requisições sem alocar recursos completos.
- **Filtragem de IPs**: Bloquear IPs suspeitos baseados em comportamento.
- **Threshold de Conexões**: Limitar número de conexões por IP.

---

## 📊 Estatísticas Relevantes

- **Tamanho médio de ataques DDoS** em 2024: ~500 Gbps.
- **Maior ataque registrado**: 3.47 Tbps (Google, 2023).
- **Duração média**: 15-30 minutos, mas pode se estender por dias.
- **Setores mais visados**: 
  - Finanças (27%)
  - Jogos (23%)
  - Tecnologia (18%)
- **Custo médio por ataque**: US$ 50.000 a US$ 2 milhões (dependendo do porte).

---

## 🚨 Sinais de um Ataque DDoS

- ⚠️ Lentidão ou indisponibilidade do site/serviço.
- ⚠️ Picos anormais de tráfego em horários incomuns.
- ⚠️ Erros de tempo limite (timeout) em requisições.
- ⚠️ Aumento no consumo de CPU/memória sem causa aparente.
- ⚠️ Logs com muitas requisições de IPs aleatórios.

---

## 🧠 Diferença: DoS vs DDoS

| Característica | DoS (Denial of Service) | DDoS (Distributed) |
|----------------|-------------------------|---------------------|
| **Origem** | Única fonte | Múltiplas fontes (botnet) |
| **Escala** | Menor | Massiva (Tbps) |
| **Dificuldade** | Mais fácil de bloquear | Muito difícil de mitigar |
| **Exemplo** | Ping Flood de uma única máquina | 10.000 dispositivos atacando juntos |

---

## ⚖️ Aspectos Legais

- **Criminalização**: Ataques DDoS são considerados crimes cibernéticos na maioria dos países.
- **Penas**: Multas pesadas e até prisão (ex: EUA - até 10 anos; Brasil - Lei Carolina Dieckmann).
- **Responsabilidade**: Empresas são responsáveis por proteger dados de clientes contra ataques.

---

## 🔗 Referências e Links Úteis

- [NIST DDoS Guide](https://www.nist.gov/)
- [Cloudflare DDoS Report](https://radar.cloudflare.com/)
- [US-CERT DDoS Resources](https://www.us-cert.gov/)
- [OWASP DDoS Prevention](https://owasp.org/)

---

## 📖 Casos Famosos

| Ano | Alvo | Impacto |
|-----|------|---------|
| 2016 | Dyn DNS | Interrompeu Twitter, Netflix, Reddit, Spotify (Mirai botnet) |
| 2020 | AWS | Ataque de 2.3 Tbps - maior da época |
| 2022 | Cloudflare | Ataque de 71 milhões de req/seg (HTTPS DDoS) |
| 2023 | Google | Ataque de 3.47 Tbps - novo recorde |

---

> ⚠️ **Nota**: Este documento tem caráter educacional. Realizar ataques DDoS é **ilegal** e pode resultar em severas penalidades legais. Utilize este conhecimento apenas para fins de defesa e conscientização.

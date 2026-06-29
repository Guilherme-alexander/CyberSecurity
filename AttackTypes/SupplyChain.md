# Supply Chain Attacks (Ataques à Cadeia de Suprimentos)

## 📌 Definição

Um ataque à cadeia de suprimentos (Supply Chain Attack) é uma modalidade de ciberataque que visa explorar vulnerabilidades em fornecedores, parceiros ou componentes de software/hardware de uma organização para comprometer o alvo final. Em vez de atacar diretamente a empresa-alvo, os atacantes infiltram-se em pontos mais fracos da cadeia de fornecimento, utilizando a confiança estabelecida entre as partes como vetor de propagação.

---

## 🧠 Como Funciona

O ataque geralmente segue estas etapas:

1. **Reconhecimento**: O atacante mapeia a cadeia de suprimentos da vítima, identificando fornecedores, dependências e componentes críticos.
2. **Comprometimento**: O atacante explora vulnerabilidades em um fornecedor, dependência ou ferramenta de desenvolvimento.
3. **Inserção de Payload**: Código malicioso é inserido em um componente legítimo (software, firmware, hardware, etc.).
4. **Propagação**: O componente comprometido é distribuído para clientes e parceiros através dos canais oficiais.
5. **Ativação**: O código malicioso é executado nos sistemas das vítimas, podendo roubar dados, instalar backdoors ou causar danos.

---

## 🧩 Variantes de Ataques à Cadeia de Suprimentos

| Tipo | Descrição | Exemplo |
|------|-----------|---------|
| **Comprometimento de Dependências** | Ataque a bibliotecas/pacotes de código aberto usados por desenvolvedores. | Event-stream (NPM) - 2018 |
| **Supply Chain de Hardware** | Inserção de backdoors ou componentes maliciosos em dispositivos físicos. | Supermicro - 2018 (alegado) |
| **Comprometimento de Ferramentas de CI/CD** | Injeção de malware em pipelines de build e deploy. | Codecov - 2021 |
| **Ataque a Fornecedores de Software** | Comprometimento de empresas de software para distribuir atualizações maliciosas. | SolarWinds - 2020 |
| **Ataque a Repositórios de Código** | Injeção de código malicioso em repositórios públicos ou privados. | PHP Git Server - 2021 |
| **Comprometimento de Certificados** | Uso de certificados digitais roubados para assinar malware. | Stuxnet, Flame |
| **Ataque a Fornecedores de Nuvem** | Exploração de vulnerabilidades em provedores de nuvem. | Capital One - 2019 |

---

## 📊 Casos Reais Notórios

### 1. **SolarWinds (2020)**
- **Impacto**: Um dos ataques mais sofisticados da história.
- **Mecanismo**: Backdoor inserido em atualizações do software Orion, afetando mais de 18.000 clientes.
- **Vítimas**: Incluíam agências governamentais dos EUA (FireEye, DHS, DOJ) e grandes corporações.
- **Duração**: O ataque ficou indetectado por meses.

### 2. **Codecov (2021)**
- **Impacto**: Script de bash comprometido por 2 meses.
- **Mecanismo**: Modificação de script de upload de cobertura de código.
- **Vítimas**: Centenas de empresas, incluindo tech giants e entidades governamentais.

### 3. **Event-Stream (2018)**
- **Impacto**: Biblioteca NPM popular comprometida.
- **Mecanismo**: Pacote malicioso Flatmap-stream inserido como dependência.
- **Vítimas**: Projetos que utilizavam a biblioteca para Bitcoin wallet.

### 4. **Kaseya (2021)**
- **Impacto**: Ransomware afetou clientes globalmente.
- **Mecanismo**: Atualização maliciosa do software VSA.
- **Vítimas**: Mais de 1.500 empresas em 17 países.

---

## 🛡️ Como se Proteger

### 🔍 **Medidas Preventivas**

- ✅ **Inventário completo**: Mapeie todos os fornecedores, dependências e componentes utilizados.
- ✅ **Verificação de integridade**: Utilize checksums e assinaturas digitais para validar software/atualizações.
- ✅ **Política de fornecedores**: Exija avaliações de segurança de todos os fornecedores.
- ✅ **Princípio do menor privilégio**: Limite permissões de acesso em toda a cadeia.
- ✅ **SBOM (Software Bill of Materials)**: Mantenha e atualize lista de todos os componentes de software.
- ✅ **Container security**: Utilize ferramentas de scanning em imagens de containers.

### 🛠️ **Detecção e Resposta**

- ✅ **Monitoramento contínuo**: Análise de comportamento anômalo em sistemas.
- ✅ **Zero Trust Architecture**: Nunca confie, sempre verifique.
- ✅ **Planos de resposta**: Tenha planos específicos para incidentes na cadeia de suprimentos.
- ✅ **Auditoria de terceiros**: Realize auditorias regulares em fornecedores críticos.

---

## 🧰 Ferramentas e Práticas Recomendadas

| Categoria | Ferramentas |
|-----------|-------------|
| **Análise de Dependências** | Snyk, Dependabot, OWASP Dependency Check |
| **SBOM** | Syft, SPDX, CycloneDX |
| **Container Scanning** | Trivy, Clair, Anchore |
| **Software Composition Analysis** | Black Duck, Sonatype Nexus |
| **Asset Discovery** | Shodan, Censys, Intruder |
| **Certificate Transparency** | Cert Spotter, crt.sh |
| **Zero Trust** | BeyondCorp, Zscaler, Cloudflare Access |

---

## 📈 Estatísticas e Tendências

- **Aumento**: Ataques à cadeia de suprimentos aumentaram **430%** em 2021 comparado a 2020 (Sonatype).
- **Impacto**: Cerca de **62%** das empresas foram afetadas por ataques à cadeia de suprimentos em 2022.
- **Custo Médio**: Um ataque à cadeia de suprimentos custa em média **$4.46 milhões** por incidente (IBM).
- **Dependências**: Projetos JavaScript têm média de **700+** dependências diretas e indiretas.
- **Tempo de Detecção**: Média de **287 dias** para detectar um ataque à cadeia de suprimentos.

---

## 🎯 Principais Desafios

| Desafio | Descrição |
|---------|-----------|
| **Visibilidade Limitada** | Dificuldade em rastrear todos os componentes de terceiros. |
| **Transitividade** | Vulnerabilidades em dependências indiretas são difíceis de mapear. |
| **Supply Chain de Código Aberto** | Grande volume de dependências open source com níveis variados de segurança. |
| **Complexidade de Atualizações** | Atualizações de segurança em dependências podem quebrar funcionalidades. |
| **Falsificações de Identidade** | Typosquatting em pacotes (ex: request vs requrst). |

---

## 🔬 Técnicas Avançadas de Ataque

### ✅ **Typosquatting**
Criação de pacotes com nomes similares a bibliotecas populares (ex: `axios` vs `axois`).

### ✅ **Dependency Confusion**
Exploração de falhas em gerenciadores de pacotes que priorizam pacotes públicos sobre privados.

### ✅ **Protótipo Poluição**
Injeção de propriedades maliciosas em objetos JavaScript compartilhados.

### ✅ **Ataque a Pipelines de Build**
Comprometimento de servidores de integração contínua para injetar malware em builds.

### ✅ **Watering Hole**
Comprometimento de sites frequentemente visitados por desenvolvedores para distribuir malware.

---

## 📘 Exemplo Prático de Ataque

**Cenário**: Empresa de software que utiliza biblioteca open source `json-utils` no backend.

```
1. Atacante descobre vulnerabilidade no pacote `json-utils@1.2.3`
2. Cria PR malicioso com correção mas com código oculto para coletar variáveis de ambiente
3. Após aprovação, publica nova versão `json-utils@1.2.4`
4. Empresa atualiza dependência via `npm update`
5. Malware captura AWS_KEYS, DB_PASSWORDS, JWT_SECRETS
6. Atacante usa credenciais para acessar a infraestrutura da empresa
7. Dados de clientes são exfiltrados
```

**Como prevenir**:
- Verificar todas as mudanças de dependências em `package-lock.json` ou `yarn.lock`
- Utilizar ferramentas de análise SCA (Software Composition Analysis)
- Implementar revisão de código de todas as contribuições externas
- Utilizar registros de pacotes com verificação de integridade (ex: npm audit)

---

## 🔗 Padrões e Regulamentações

| Padrão/Regulamentação | Descrição |
|-----------------------|-----------|
| **NIST SP 800-161** | Guia para gerenciamento de riscos na cadeia de suprimentos de sistemas de informação. |
| **CIS Controls** | Controles específicos para segurança na cadeia de suprimentos. |
| **ISO/IEC 27036** | Diretrizes para segurança da informação em relações com fornecedores. |
| **Executive Order 14028 (EUA)** | Exigência de SBOM para agências governamentais. |
| **LGPD/GDPR** | Responsabilidade por dados em toda a cadeia de processamento. |

---

## 🔗 Referências e Links Úteis

- [OWASP Software Supply Chain Security](https://owasp.org/www-project-software-supply-chain-security/)
- [CISA - Supply Chain Security](https://www.cisa.gov/supply-chain-security)
- [NIST - Cybersecurity Supply Chain Risk Management](https://www.nist.gov/cyberframework)
- [Sonatype - State of the Software Supply Chain Report](https://www.sonatype.com/state-of-the-software-supply-chain)
- [SBOM Forum](https://sbomforum.org/)
- [OpenSSF - Supply Chain Integrity](https://openssf.org/working-groups/identifying-security-threats/)

---

> ⚠️ **Nota**: A segurança da cadeia de suprimentos é um esforço contínuo que requer comprometimento de toda a organização. Em caso de suspeita de comprometimento, isole imediatamente o componente afetado e envolva a equipe de resposta a incidentes.

---

## 📊 Checklist de Segurança

- [ ] Mapeamento completo de fornecedores e dependências
- [ ] Implementação de SBOM atualizado
- [ ] Verificação de integridade de todas as atualizações
- [ ] Política formal de avaliação de fornecedores
- [ ] Ferramentas de SCA implementadas
- [ ] Plano de resposta a incidentes específico
- [ ] Treinamento da equipe sobre riscos na cadeia de suprimentos
- [ ] Monitoramento contínuo de CVE que afetam dependências
- [ ] Revisão de permissões e acessos de fornecedores
- [ ] Testes de penetração em componentes críticos

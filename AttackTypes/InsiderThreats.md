# Insider Threats (Ameaças Internas)

## 📌 Definição

Ameaças internas (Insider Threats) são riscos de segurança originados por pessoas dentro de uma organização – funcionários, ex-funcionários, contratados, parceiros de negócios ou estagiários – que possuem acesso autorizado a sistemas, dados ou instalações e utilizam esse acesso de forma maliciosa ou negligente, causando danos à organização. Estes ataques são particularmente perigosos porque os insiders já possuem permissões legítimas, tornando suas ações mais difíceis de detectar.

---

## 🧠 Como Funciona

O ataque interno geralmente segue estas etapas:

1. **Acesso Legítimo**: O insider possui credenciais e permissões válidas para sistemas e dados.

2. **Motivação**: Pode ser movido por:
   - **Financeira**: Venda de dados ou propriedade intelectual
   - **Pessoal**: Descontentamento, vingança, ego
   - **Ideológica**: Espionagem industrial, ativismo
   - **Coerção**: Chantagem, ameaças externas
   - **Negligência**: Erros, falta de treinamento, descuido

3. **Ação Maliciosa/Descuidada**:
   - Exfiltração de dados
   - Instalação de backdoors
   - Sabotagem de sistemas
   - Venda de informações confidenciais
   - Compartilhamento acidental de dados

4. **Encobrimento**: Pode tentar esconder atividades apagando logs, usando contas de outros, ou operando fora do horário comercial.

5. **Impacto**: Perda financeira, dano à reputação, violação regulatória, perda de vantagem competitiva.

---

## 🧩 Tipos de Ameaças Internas

| Categoria | Descrição | Subcategorias |
|-----------|-----------|---------------|
| **Malicioso (Intencional)** | Ações deliberadas para causar dano | - Roubo de propriedade intelectual<br>- Espionagem corporativa<br>- Sabotagem<br>- Fraude financeira<br>- Venda de dados |
| **Negligente (Não Intencional)** | Ações sem intenção maliciosa, mas com consequências | - Erro humano<br>- Falta de treinamento<br>- Compartilhamento excessivo<br>- Uso de dispositivos pessoais<br>- Senhas fracas |
| **Comprometido** | Insider cujas credenciais foram roubadas | - Credenciais em breaches<br>- Ataques de phishing bem-sucedidos<br>- Engenharia social<br>- Malware em dispositivos |
| **Terceiros** | Fornecedores, parceiros, contratados | - Acesso excessivo a dados<br>- Falta de fiscalização<br>- Vulnerabilidades em sistemas parceiros |
| **Privilégios Elevados** | Administradores com amplo acesso | - Abuso de poder<br>- Escalonamento de privilégios<br>- Manipulação de logs |

---

## 📊 Estatísticas Relevantes

- **Frequência**: **34%** das violações de dados envolvem atores internos (Verizon DBIR 2024).
- **Custo Médio**: $4.9 milhões por incidente de ameaça interna (Ponemon Institute).
- **Tempo de Detecção**: Média de **85 dias** para detectar uma ameaça interna.
- **Motivação Primária**: **62%** são motivados por ganho financeiro.
- **Negligência**: **23%** dos incidentes são causados por erro humano.
- **Ex-funcionários**: **18%** das ameaças internas vêm de ex-funcionários.
- **Setores Mais Visados**: Financeiro, Saúde, Tecnologia, Governo.
- **Acesso**: **70%** dos insiders usam seus próprios acessos para atividades maliciosas.
- **Identificação**: Empresas com UBA (User Behavior Analytics) detectam **60%** mais rápido.

---

## 🎯 Indicadores de Comportamento Suspeito

### ✅ **Indicadores Técnicos**

| Comportamento | Descrição |
|---------------|-----------|
| **Acesso a Dados Incomuns** | Acessar arquivos fora da função, especialmente à noite ou finais de semana |
| **Volume de Download** | Baixar grandes quantidades de dados |
| **Dispositivos USB** | Uso frequente ou não autorizado de dispositivos removíveis |
| **Privilégios Escalados** | Tentativas de elevar permissões de acesso |
| **Acesso a Sistemas Não Usuais** | Acessar servidores ou aplicações não relacionadas ao trabalho |
| **Alteração de Dados** | Modificação, exclusão ou criptografia de arquivos |
| **Transferências de Dados** | Envio de dados para e-mails pessoais, cloud storage externa |
| **Logs Apagados** | Tentativas de remover rastros de atividades |
| **Múltiplas Falhas de Login** | Tentativas de acesso a contas de outros usuários |
| **Conexões Suspeitas** | Comunicação com IPs ou domínios desconhecidos |

### ✅ **Indicadores Comportamentais**

| Comportamento | Descrição |
|---------------|-----------|
| **Descontentamento** | Queixas frequentes, insatisfação com a empresa |
| **Problemas Financeiros** | Dificuldades financeiras pessoais |
| **Afastamento** | Isolamento social, comportamento defensivo |
| **Interesse por Segurança** | Perguntas excessivas sobre controles de segurança |
| **Horários Irregulares** | Trabalhar em horários incomuns, especialmente madrugada |
| **Recusa de Férias** | Evitar se afastar dos sistemas |
| **Conflitos** | Disputas com colegas ou superiores |
| **Papel de Saída** | Funcionários que pediram demissão ou foram demitidos |
| **Mudança de Comportamento** | Alteração repentina no padrão de trabalho |
| **Curiosidade** | Interesse em dados além da função |

---

## 🛡️ Como se Proteger

### 🔒 **Medidas Preventivas**

- ✅ **Princípio do Menor Privilégio**: Conceder acesso mínimo necessário para função.
- ✅ **Segregação de Funções**: Dividir tarefas críticas entre múltiplas pessoas.
- ✅ **Revisão de Acessos**: Auditoria regular de permissões de usuários.
- ✅ **Onboarding e Offboarding**: Processos rigorosos de entrada e saída de funcionários.
- ✅ **Treinamento Contínuo**: Conscientização sobre segurança, phishing, engenharia social.
- ✅ **Política de Uso Aceitável**: Regras claras sobre uso de dados e dispositivos.
- ✅ **Criptografia de Dados**: Dados em repouso e em trânsito sempre criptografados.
- ✅ **Autenticação Multifator (MFA)**: Obrigatória para acesso a sistemas críticos.
- ✅ **Controle de Dispositivos**: Bloqueio de USB, desativação de portas.
- ✅ **Política de "Clean Desk"**: Sem papéis com informações sensíveis em estações.

### 🛠️ **Medidas de Detecção**

- ✅ **User Behavior Analytics (UBA)**: Análise de padrões de comportamento anômalos.
- ✅ **Data Loss Prevention (DLP)**: Monitoramento de movimentação de dados.
- ✅ **Auditoria de Logs**: Registro centralizado e revisão de atividades.
- ✅ **SIEM**: Correlação de eventos de segurança.
- ✅ **Análise de Sentimento**: Monitoramento de satisfação dos funcionários.
- ✅ **Screen Recording**: Gravação de tela para atividades críticas (com política clara).
- ✅ **Alertas em Tempo Real**: Notificações sobre comportamentos suspeitos.

### ✅ **Medidas de Resposta**

- ✅ **Plano de Resposta**: Procedimentos específicos para incidentes internos.
- ✅ **Isolamento Rápido**: Revogação imediata de acesso em caso suspeito.
- ✅ **Coleta Forense**: Preservação de evidências para investigação.
- ✅ **Recursos Legais**: Colaboração com departamento jurídico e compliance.
- ✅ **Comunicação**: Política de comunicação com stakeholders.
- ✅ **Pós-Incidente**: Revisão e melhoria dos controles.

---

## 🧰 Ferramentas de Defesa

| Categoria | Ferramentas | Descrição |
|-----------|-------------|-----------|
| **UBA/UEBA** | Exabeam, Securonix, Splunk UBA | Análise de comportamento de usuários |
| **DLP** | Symantec DLP, Forcepoint, Digital Guardian | Prevenção de perda de dados |
| **SIEM** | Splunk, IBM QRadar, Elastic Stack | Correlação e análise de logs |
| **Identity Management** | Okta, Azure AD, Ping Identity | Gestão de identidades e acessos |
| **Privileged Access** | CyberArk, BeyondTrust | Gerenciamento de acessos privilegiados |
| **Endpoint Detection** | CrowdStrike, SentinelOne, Carbon Black | Detecção em endpoints |
| **Data Classification** | Varonis, Netwrix, SailPoint | Classificação de dados sensíveis |
| **Insider Risk** | Microsoft Purview, DTEX Systems | Soluções especializadas em risco interno |

---

## 📘 Exemplo Prático

**Cenário 1: Funcionário Descontente**

```
Funcionário de TI, João, é demitido após 5 anos na empresa.
Durante seu período de aviso, ele:

1. Acessa o repositório de código fonte da empresa
2. Faz download de 500GB de dados, incluindo segredos comerciais
3. Cria uma conta de backdoor para acessar após sua saída
4. Planeja vender os dados para concorrente

DETECÇÃO:
- UBA detecta volume anormal de downloads
- Acesso ocorre após as 23h e em finais de semana
- Alerta de DLP: transferência de dados para nuvem externa

AÇÃO:
- Congelamento imediato da conta do usuário
- Isolamento da máquina para coleta forense
- Equipe jurídica notificada
- Investigação completa com cyber forense
- Revisão de acessos de outros funcionários
```

**Cenário 2: Erro Humano Não Intencional**

```
Maria, gerente de RH, prepara um e-mail com dados salariais de 200 funcionários.
Por engano, ela envia o arquivo para todos@empresa.com em vez de rh@empresa.com

DETECÇÃO:
- DLP identifica dados sensíveis em e-mail para grande grupo
- Bloqueia automaticamente o envio
- Notifica Maria e a equipe de segurança

AÇÃO:
- Treinamento adicional sobre classificação de dados
- Ajuste nas permissões de envio de dados sensíveis
- Refinamento das regras DLP
- Sem consequências disciplinares (foco em conscientização)
```

---

## ⚖️ Aspectos Legais e Compliance

### ✅ **Leis e Regulamentações**

| Regulamentação | Requisito |
|----------------|-----------|
| **LGPD (Brasil)** | Proteção de dados pessoais, notificação de violações, responsabilidade |
| **GDPR (EUA)** | Notificação em 72h, princípio da minimização, direito de esquecimento |
| **HIPAA** | Proteção de dados de saúde, auditoria de acessos |
| **PCI DSS** | Controle de acesso a dados de cartão, monitoramento |
| **SOX** | Controles internos para dados financeiros, auditoria |
| **NIST** | Orientações sobre gerenciamento de ameaças internas |

### ✅ **Políticas Recomendadas**

- ✅ Política de Uso Aceitável (AUP) assinada por todos
- ✅ Código de conduta claro
- ✅ Política de Whistleblower (denúncia segura)
- ✅ Cláusulas de confidencialidade em contratos
- ✅ Política de monitoramento com transparência
- ✅ Procedimentos de resposta a incidentes internos

---

## 🔬 Técnicas Avançadas de Mitigação

### ✅ **Práticas de Segurança Psicológica**

| Prática | Descrição |
|---------|-----------|
| **Programas de Bem-Estar** | Apoio psicológico, gestão de estresse |
| **Cultura de Transparência** | Comunicação aberta entre níveis hierárquicos |
| **Reconhecimento** | Programas de valorização de funcionários |
| **Canais de Denúncia** | Mecanismos seguros para reportar preocupações |
| **Mediação de Conflitos** | Resolução de disputas internas |

### ✅ **Medidas Técnicas Avançadas**

| Medida | Descrição |
|--------|-----------|
| **Zero Trust Architecture** | Nunca confiar, sempre verificar |
| **Microssegmentação** | Isolamento de redes para limitar movimentação lateral |
| **Analytics Preditivo** | IA para prever comportamentos de risco antes de ocorrerem |
| **Canary Tokens** | Dados falsos para identificar exfiltração |
| **Rastreamento de Conteúdo** | Marcação digital de documentos confidenciais |
| **Browser Isolation** | Execução de conteúdo externo em sandbox |

---

## 📊 Matriz de Risco de Insider

| Tipo de Ameaça | Probabilidade | Impacto | Prioridade |
|----------------|---------------|---------|------------|
| **Negligente** | Alta | Médio | Alta |
| **Malicioso (Funcionário)** | Média | Alto | Crítica |
| **Malicioso (Ex-funcionário)** | Média | Alto | Crítica |
| **Comprometido** | Alta | Alto | Crítica |
| **Terceiro (Parceiro)** | Média | Médio/Alto | Alta |
| **Contratado** | Baixa/Média | Médio | Média |

---

## 📋 Checklist de Prevenção

### ✅ **Prevenção**
- [ ] Política de menor privilégio implementada
- [ ] MFA obrigatório para todos os usuários
- [ ] Treinamento de segurança para todos os funcionários
- [ ] Classificação de dados implementada
- [ ] Acordos de confidencialidade assinados
- [ ] Onboarding e offboarding padronizados
- [ ] Política de uso aceitável definida

### ✅ **Detecção**
- [ ] Soluções UBA/UEBA implementadas
- [ ] DLP ativo e configurado
- [ ] SIEM centralizado e monitorado
- [ ] Auditoria de acessos regular
- [ ] Logs revisados periodicamente
- [ ] Alertas de comportamento anômalo configurados

### ✅ **Resposta**
- [ ] Plano de resposta a incidentes interno definido
- [ ] Times de resposta treinados
- [ ] Procedimentos forenses documentados
- [ ] Canais legais preparados
- [ ] Política de comunicação definida
- [ ] Análise pós-incidente incluída

---

## 🔗 Referências e Links Úteis

- [CERT - Insider Threat Center](https://www.cert.org/insider-threat/)
- [NIST SP 800-53 - Insider Threat Controls](https://www.nist.gov/)
- [Ponemon Institute - Insider Threat Reports](https://www.ponemon.org/)
- [Verizon DBIR - Insider Section](https://www.verizon.com/business/resources/reports/dbir/)
- [MITRE - Insider Threat Guide](https://www.mitre.org/)
- [SANS - Insider Threat Resources](https://www.sans.org/insider-threat/)
- [OWASP - Insider Threats](https://owasp.org/www-project-insider-threat/)

---

> ⚠️ **Nota**: Ameaças internas representam um dos maiores desafios de segurança cibernética. A abordagem mais eficaz combina tecnologia, processos e cultura organizacional. O objetivo não é criar um ambiente de desconfiança, mas sim um ambiente onde comportamentos de risco sejam detectados e mitigados precocemente, protegendo tanto a organização quanto os funcionários.

---

## 📊 Diferenciação Entre Tipos de Insider

| Aspecto | Malicioso | Negligente | Comprometido |
|---------|-----------|------------|--------------|
| **Intenção** | Deliberada | Acidental | Involuntária |
| **Consciência** | Sabe que está errado | Geralmente não percebe | Pode não saber |
| **Motivação** | Financeira, vingança, ideologia | Distração, pressa, desconhecimento | Externo (hacker) |
| **Ações** | Roubo, sabotagem | Erro de envio, senha fraca | Credencial roubada |
| **Detecção** | Difícil (tenta esconder) | Mais fácil (ações visíveis) | Difícil (parece normal) |
| **Punição** | Demissão, processo legal | Treinamento, advertência | Medidas de segurança, MFA |
| **Prevenção** | Controles rigorosos | Treinamento constante | Autenticação forte, monitoramento |

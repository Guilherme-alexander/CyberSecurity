# Impersonation (Suplantação de Identidade)

## 📌 Definição

Impersonation, ou suplantação de identidade, é uma técnica de engenharia social onde um atacante se passa por uma pessoa, organização ou entidade confiável para enganar vítimas e obter informações sensíveis, acesso a sistemas, transferências financeiras ou outras ações prejudiciais. Diferentemente do phishing genérico, a suplantação frequentemente envolve pesquisa detalhada sobre a vítima e o alvo, tornando o ataque mais convincente e difícil de detectar.

---

## 🧠 Como Funciona

O ataque de suplantação geralmente segue estas etapas:

1. **Pesquisa e Coleta de Informações**: O atacante estuda a vítima e o alvo:
   - Redes sociais (LinkedIn, Facebook, Instagram)
   - Sites corporativos e comunicados oficiais
   - Relações públicas e anúncios de novos funcionários
   - E-mails vazados em breaches anteriores
   - Estrutura organizacional e hierarquia

2. **Criação do Persona**: 
   - Criação de contas falsas ou comprometimento de contas reais
   - Configuração de e-mails, perfis sociais, números de telefone
   - Estudo do estilo de comunicação, jargão e tom

3. **Abordagem Inicial**: Contato com a vítima através de:
   - E-mail (email spoofing ou contas falsas)
   - Telefone (vishing)
   - SMS (smishing)
   - Redes sociais (DMs)
   - Presencialmente (em eventos, escritórios)

4. **Exploração**: Utiliza o relacionamento construído para:
   - Solicitar informações confidenciais
   - Pedir transferências financeiras
   - Obter credenciais de acesso
   - Solicitar alterações em sistemas
   - Extrair dados sensíveis

5. **Conclusão**: O atacante alcança seu objetivo e desaparece, frequentemente deixando a vítima sem suspeitar até que o dano seja descoberto.

---

## 🧩 Tipos de Suplantação de Identidade

| Tipo | Descrição | Exemplos |
|------|-----------|----------|
| **Suplantação de Executivos (CEO Fraud)** | Atacante se passa por CEO ou diretor para autorizar transações | "Preciso que transfira R$ 500 mil para este fornecedor hoje" |
| **Suplantação de Fornecedores** | Fingir ser um parceiro comercial confiável | "Atualizamos nossa conta bancária, use este novo IBAN" |
| **Suplantação de Funcionários** | Se passar por novo funcionário ou colega | "Sou do novo time de auditoria, preciso de acesso ao sistema" |
| **Suplantação de Autoridades** | Fingir ser órgão regulador, polícia, fiscal | "Estamos investigando sua empresa, precisamos de documentos" |
| **Suplantação de TI/Suporte** | Se passar por equipe de tecnologia | "Detectamos um problema no seu computador, instale este software" |
| **Suplantação de RH** | Fingir ser departamento pessoal | "Precisamos confirmar seus dados bancários para o pagamento" |
| **Suplantação de Clientes** | Se passar por cliente para obter informações | "Sou o Sr. Silva, preciso do relatório de vendas de janeiro" |
| **Suplantação de Mídia** | Fingir ser jornalista/entrevistador | "Sou da revista X, gostaria de uma entrevista sobre..." |
| **Deepfake Impersonation** | Uso de IA para imitar voz ou vídeo | Chamada de vídeo com CEO falso pedindo transferência |

---

## 📊 Estatísticas Relevantes

- **Frequência**: **62%** das organizações sofreram ataques de suplantação em 2023 (Proofpoint).
- **Custo Médio**: $3.5 milhões por incidente de CEO Fraud (FBI IC3).
- **Aumento**: Aumento de **87%** em ataques de suplantação nos últimos 2 anos.
- **Setores Mais Visados**: Financeiro (38%), Tecnologia (22%), Governo (15%).
- **Canais**: E-mail (74%), Telefone (21%), Redes Sociais (5%).
- **Taxa de Sucesso**: **30%** dos ataques de suplantação são bem-sucedidos na primeira tentativa.
- **Tempo de Detecção**: Média de **42 dias** para detectar suplantação.
- **Treinamento**: Empresas com treinamento reduzem sucesso de ataques em **70%**.

---

## 🎯 Técnicas Comuns de Impersonation

| Técnica | Descrição | Exemplo |
|---------|-----------|---------|
| **Email Spoofing** | Falsificação do endereço "De:" | E-mail que parece vir do CEO@empresa.com |
| **Display Name Spoofing** | Falsificação do nome exibido | "João Silva (CEO)" mas com e-mail aleatório |
| **Domain Spoofing** | Domínio similar ao legítimo | @empresa-segura.com vs @empresa-segura.co |
| **Lookalike Domains** | Domínios com caracteres similares | @empresα.com (com alfa em vez de a) |
| **Comprometimento de Conta** | Invasão de conta real do executivo | E-mail enviado da conta verdadeira do CEO |
| **Typosquatting** | Erro de digitação proposital | @goggle.com em vez de @google.com |
| **Vishing** | Chamada telefônica fingindo ser autoridade | "Sou da Receita Federal, seu CPF está irregular" |
| **Smishing** | SMS falso com link malicioso | "Seu pedido foi liberado. Confirme aqui." |
| **Deepfake Voice** | Clonagem de voz com IA | Chamada: "Sou o Presidente, autorize esta transferência" |
| **Deepfake Video** | Vídeo falso de executivo | Zoom call com CEO falso |

---

## 🛡️ Como se Proteger

### ✅ **Para Usuários Finais**

- ✅ **Verifique sempre o remetente**: Olhe o e-mail completo, não apenas o nome.
- ✅ **Confirme por outro canal**: Se receber pedido suspeito, confirme por telefone/WhatsApp.
- ✅ **Desconfie de urgência**: Ataques criam senso de urgência para evitar verificação.
- ✅ **Nunca compartilhe credenciais**: Nenhum sistema legítimo pede senha por e-mail/telefone.
- ✅ **Cuidado com dados pessoais**: Não publique informações detalhadas sobre cargo/função.
- ✅ **Use MFA**: Autenticação multifator impede acesso mesmo com senha roubada.
- ✅ **Reporte suspeitas**: Informe imediatamente a equipe de segurança.

### ✅ **Para Empresas**

- ✅ **Implemente autenticação de e-mail**: SPF, DKIM, DMARC para prevenir spoofing.
- ✅ **Política de verificação**: Aprovação em duas etapas para transações financeiras.
- ✅ **Treinamento contínuo**: Simulações regulares de ataques de suplantação.
- ✅ **Sistemas de verificação**: Códigos secretos entre executivos para confirmação.
- ✅ **Monitoramento de domínios**: Detectar registros de domínios similares.
- ✅ **Análise de comportamento**: UBA para detectar anomalias em comunicações.
- ✅ **Gestão de identidade**: Revisão regular de acessos e permissões.
- ✅ **Cultura de verificação**: Incentivar "desconfiar" e "confirmar" sem constrangimento.

---

## 🧰 Ferramentas de Defesa

| Categoria | Ferramentas | Descrição |
|-----------|-------------|-----------|
| **Autenticação de E-mail** | SPF, DKIM, DMARC | Validação de remetentes |
| **Anti-Spoofing** | Microsoft Defender, Proofpoint | Detecção de spoofing em e-mails |
| **Análise de Domínio** | Domaintools, WhoisXML | Monitoramento de domínios suspeitos |
| **Verificação de Identidade** | Onfido, Trulioo, Jumio | Verificação biométrica |
| **Deepfake Detection** | Microsoft Video Authenticator, Reality Defender | Detecção de mídia manipulada |
| **UBA/UEBA** | Exabeam, Splunk UBA | Análise de comportamento de usuários |
| **SIEM** | Splunk, IBM QRadar | Correlação de eventos |
| **DLP** | Symantec, Forcepoint | Prevenção de perda de dados |

---

## 📘 Exemplos Práticos

### Exemplo 1: CEO Fraud

**E-mail Falso:**
```
De: Carlos Silva (CEO) <carlos.silva@empresa-correto.com>
Para: Maria Santos (Financeiro) <maria.santos@empresa.com.br>
Assunto: URGENTE - Transferência para novo fornecedor

Maria,

Estamos fechando um contrato sigiloso com novo fornecedor.
Faça uma transferência de R$ 450.000,00 para a conta abaixo URGENTE.
O contrato será assinado amanhã e precisamos do comprovante hoje.

Dados:
Banco: XYZ
Agência: 1234
Conta: 56789-0
CNPJ: 12.345.678/0001-99

Aguardando confirmação.
Carlos
```

**Como identificar:**
- ❌ Pedido de transferência sem processo formal
- ❌ Urgência incomum
- ❌ "Contrato sigiloso" não documentado
- ❌ Conta bancária desconhecida
- ✅ Verificar com CEO por telefone separado
- ✅ Verificar sistema interno de fornecedores

---

### Exemplo 2: Suplantação de Fornecedor

**E-mail Falso:**
```
De: Fornecedor XYZ <faturamento@xyz-fornecedor-seguro.com>
Para: Compras <compras@empresa.com.br>
Assunto: Alteração de dados bancários

Prezados,

Informamos que nossa conta bancária foi alterada.
A partir de hoje, utilize os novos dados:

Banco: ABC
Agência: 7890
Conta: 12345-6
CNPJ: 98.765.432/0001-11

Favor atualizar em seu sistema.
Atenciosamente,
João Silva (Financeiro)
```

**Como identificar:**
- ❌ E-mail de alteração de dados sem aviso prévio
- ❌ Domínio do e-mail com ligeira diferença (.com vs .com.br)
- ❌ "Assunto: Alteração de dados bancários" não menciona contrato
- ✅ Verificar por telefone com número oficial do fornecedor
- ✅ Verificar no sistema de fornecedores a validade do CNPJ

---

### Exemplo 3: Deepfake Voice (Cenário Avançado)

**Chamada Telefônica:**
```
Voz (IA): "Olá, sou a Ana, Diretora de Finanças. Preciso que autorize
uma transferência internacional de US$ 2M para nosso novo parceiro
na China. O contrato está em andamento e precisa ser concluído hoje."
```

**Como identificar:**
- ❌ Ligação fora do padrão normal
- ❌ Pedido sem documentação prévia
- ❌ "Novo parceiro" sem processo de homologação
- ✅ Solicitar comprovante por e-mail para verificação
- ✅ Confirmar através de canal secundário (WhatsApp, Teams)
- ✅ Verificar com outro executivo

---

## ⚖️ Aspectos Legais

| Aspecto | Descrição |
|---------|-----------|
| **Responsabilidade** | Empresa pode ser responsabilizada por não ter controles adequados |
| **Proteção de Dados** | LGPD/GDPR exigem notificação de violações em 72h |
| **Fraude Financeira** | A suplantação pode configurar estelionato (Art. 171 do Código Penal) |
| **Falsificação de Documentos** | Pode configurar falsificação (Art. 297 do Código Penal) |
| **Due Diligence** | Empresas devem demonstrar esforços razoáveis de prevenção |

---

## 🔬 Técnicas Avançadas de Defesa

### ✅ **Autenticação de Comunicações**

| Método | Descrição |
|--------|-----------|
| **Código de Verificação** | Palavra/pin secreto entre executivos para confirmar identidade |
| **Assinatura Digital** | E-mails críticos assinados com certificados digitais |
| **BIOMETRIA** | Impressão digital, íris, reconhecimento facial para autorizações |
| **Verificação Cruzada** | Sempre confirmar pedidos críticos por múltiplos canais |
| **Política de "Two-Person Rule"** | Transações financeiras requerem aprovação de 2 pessoas |

### ✅ **Análise de Comunicação**

| Método | Descrição |
|--------|-----------|
| **Linguagem Natural** | Análise de estilo de escrita (NLU) para detectar anomalias |
| **Sentiment Analysis** | Detecção de tom emocional incomum |
| **Contextual Awareness** | Análise de padrões históricos de comunicação |
| **Real-time Verification** | Alertas instantâneos sobre comunicações suspeitas |

---

## 📊 Matriz de Risco de Impersonation

| Alvo | Probabilidade | Impacto | Risco | Prioridade de Defesa |
|------|---------------|---------|-------|---------------------|
| **Financeiro** | Alta | Crítico | Crítico | Máxima |
| **RH/Dados Pessoais** | Alta | Alto | Alto | Alta |
| **TI/Infraestrutura** | Média | Alto | Alto | Alta |
| **Operações** | Média | Médio | Médio | Média |
| **Marketing** | Baixa | Baixo | Baixo | Baixa |

---

## 📋 Checklist de Prevenção

### ✅ **Para Empresas**
- [ ] SPF, DKIM, DMARC implementados
- [ ] Política de aprovação dupla para transações > R$ 50.000
- [ ] Treinamento trimestral sobre suplantação
- [ ] Simulações de CEO Fraud realizadas
- [ ] Códigos secretos entre executivos
- [ ] Monitoramento de domínios similares
- [ ] Auditoria de acessos e permissões
- [ ] Plano de resposta a incidentes atualizado

### ✅ **Para Funcionários**
- [ ] Verificar e-mail completo do remetente
- [ ] Confirmar pedidos críticos por outro canal
- [ ] Não compartilhar credenciais
- [ ] Reportar comunicações suspeitas
- [ ] Verificar domínios antes de clicar
- [ ] Não publicar informações sensíveis em redes sociais

---

## 🔗 Referências e Links Úteis

- [FBI IC3 - Business Email Compromise](https://www.ic3.gov/)
- [Proofpoint - Impersonation Report](https://www.proofpoint.com/)
- [CISA - CEO Fraud Guidance](https://www.cisa.gov/)
- [NIST - Identity Management](https://www.nist.gov/identity-access-management)
- [Gartner - Identity and Access Management](https://www.gartner.com/)
- [CERT.br - Guia de Segurança](https://cartilha.cert.br/)

---

> ⚠️ **Nota**: A suplantação de identidade explora a confiança humana em vez de vulnerabilidades técnicas. A melhor defesa é uma cultura organizacional que valorize a verificação, questione pedidos incomuns e mantenha treinamento contínuo. Nunca confie em pedidos urgentes sem confirmação independente.

---

## 📊 Comparação de Técnicas de Suplantação

| Técnica | Canal | Dificuldade | Detecção | Risco |
|---------|-------|-------------|----------|--------|
| **Display Name Spoofing** | E-mail | Baixa | Fácil | Médio |
| **Domain Spoofing** | E-mail | Média | Moderada | Alto |
| **Email Spoofing** | E-mail | Baixa | Fácil (com SPF/DKIM) | Médio |
| **Conta Comprometida** | Vários | Alta | Difícil | Crítico |
| **Vishing** | Telefone | Média | Moderada | Alto |
| **Smishing** | SMS | Baixa | Fácil | Médio |
| **Deepfake Voice** | Voz | Alta | Difícil | Crítico |
| **Deepfake Video** | Vídeo | Muito Alta | Muito Difícil | Crítico |
| **Presencial** | Físico | Alta | Difícil | Alto |

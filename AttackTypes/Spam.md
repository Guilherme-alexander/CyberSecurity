# Spam

## 📌 Definição

Spam é o envio não solicitado e massivo de mensagens eletrônicas, geralmente com fins comerciais ou maliciosos. Embora frequentemente associado a e-mails, o spam pode ocorrer em diversos canais: SMS, redes sociais, comentários em blogs, fóruns, mensageiros instantâneos e chamadas telefônicas. O termo originou-se de um sketch do grupo Monty Python, onde a palavra "spam" era repetida incessantemente em um restaurante.

---

## 🧠 Como Funciona

O spam geralmente segue estas etapas:

1. **Coleta de Endereços**: Atacantes obtêm listas de contatos através de:
   - Scraping de sites e redes sociais
   - Compra de bases de dados
   - Violações de dados (data breaches)
   - Ferramentas de força bruta para gerar combinações comuns

2. **Infraestrutura de Envio**: Utilizam servidores próprios, botnets ou servidores SMTP comprometidos.

3. **Criação de Conteúdo**: Mensagens com elementos de engenharia social, ofertas atraentes ou conteúdo alarmante.

4. **Distribuição Massiva**: Envio para milhões de destinatários com mínima personalização.

5. **Exploração/Conversão**: 
   - Venda de produtos falsos ou de baixa qualidade
   - Coleta de credenciais (phishing)
   - Instalação de malware (malvertising)
   - Amplificação de golpes financeiros

---

## 🧩 Tipos de Spam

| Categoria | Descrição | Exemplos |
|-----------|-----------|----------|
| **Spam Comercial** | Publicidade não solicitada de produtos/serviços | Viagens, remédios, empréstimos, cursos |
| **Spam Malicioso** | Contém links ou anexos perigosos | Phishing, malware, ransomware |
| **Spam de SEO** | Comentários em blogs/sites para melhorar ranking | "Ótimo post! Visite meu site..." |
| **Spam em Redes Sociais** | Mensagens indesejadas em plataformas sociais | DMs com links, comentários em massa |
| **Spam SMS (Smishing)** | Mensagens de texto não solicitadas | "Seu prêmio está disponível. Clique aqui!" |
| **Spam de Referência** | Tráfego artificial para sites | "Encontre o melhor preço em..." |
| **Spam de Fórum** | Posts não relevantes em comunidades | "Compre seu diploma aqui!" |
| **Spam de Calendário** | Convites indesejados em Google/Outlook Calendar | "Promoção exclusiva! Aceitar convite" |
| **Spam de Notificação** | Notificações push indesejadas | Sites que pedem permissão para enviar notificações |
| **Email Spoofing** | Falsificação de remetente para parecer legítimo | "Suporte da Apple" com e-mail falso |

---

## 📊 Estatísticas Relevantes

- **Total**: Mais de **300 bilhões** de e-mails spam enviados por dia.
- **Percentual**: Cerca de **45-50%** de todo o tráfego de e-mail é spam.
- **Custo Global**: Estima-se em **$20 bilhões** anuais em perdas de produtividade.
- **Taxa de Resposta**: Apenas **0.02%** dos usuários clicam em links de spam.
- **Botnets**: Mais de **80%** do spam é enviado por dispositivos comprometidos (botnets).
- **Países de Origem**: Principais emissores: China, EUA, Rússia, Índia.
- **Filtragem**: Filtros anti-spam bloqueiam cerca de **98%** do spam global.
- **Engajamento**: Golpes de "herança" e "prêmio" têm maior taxa de resposta.

---

## 🛡️ Como se Proteger

### ✅ **Para Usuários Finais**

- ✅ **Nunca responda a e-mails de spam**: Confirma que seu e-mail é ativo.
- ✅ **Evite clicar em links ou anexos**: Mesmo por curiosidade.
- ✅ **Use filtros anti-spam**: Habilitados por padrão na maioria dos serviços.
- ✅ **Cuidado com "unsubscribe"**: Em spams, pode confirmar seu endereço como válido.
- ✅ **Crie e-mails descartáveis**: Para cadastros em sites menos confiáveis.
- ✅ **Não compartilhe seu e-mail publicamente**: Use formulários de contato.
- ✅ **Reporte spam**: Marque como spam nos serviços de e-mail.
- ✅ **Verifique o remetente**: Domínios suspeitos ou com erros ortográficos.

### ✅ **Para Empresas**

- ✅ **Implemente autenticação de e-mail**: SPF, DKIM, DMARC para evitar spoofing.
- ✅ **Use gateways de e-mail com IA**: Soluções como Proofpoint, Mimecast.
- ✅ **Política de "permitir listas"**: Apenas e-mails de remetentes autorizados.
- ✅ **Treinamento de funcionários**: Identificação e reporte de spam.
- ✅ **Limite de envio por IP**: Restringir envios por remetente/hora.
- ✅ **Monitore listas de remetentes**: Verifique se a empresa está em blacklists.
- ✅ **Educação sobre "quarentena"**: Como revisar e-mails suspeitos.

---

## 🧰 Ferramentas Anti-Spam

| Categoria | Ferramentas | Descrição |
|-----------|-------------|-----------|
| **Filtros de E-mail** | Gmail, Outlook, ProtonMail | Filtros nativos com IA |
| **Gateway Anti-Spam** | Proofpoint, Mimecast, Barracuda | Soluções empresariais |
| **Blacklists** | Spamhaus, SURBL, URIBL | Listas de IPs/domínios maliciosos |
| **Verificação de Reputação** | Sender Score, Google Postmaster | Avaliação de remetentes |
| **Filtros DNSBL** | Zen.spamhaus.org, bl.spamcop.net | Bloqueio via DNS |
| **Autenticação** | SPF, DKIM, DMARC | Validação de remetentes |
| **Verificação de Anexos** | VirusTotal, ClamAV | Scanner de malware |
| **Filtros Comunitários** | SpamCop, Knujon | Reporte colaborativo |

---

## 📘 Exemplo Prático

**E-mail de Spam Típico:**
```
De: "Prêmios Internacionais" <premios@promocoes-gratis.top>
Assunto: VOCÊ GANHOU UM IPHONE 15! RESGATE AGORA

Parabéns! Seu e-mail foi sorteado no nosso concurso de fim de ano!

Você acaba de ganhar um iPhone 15 Pro Max + R$ 10.000 em dinheiro!
Esta é uma promoção exclusiva para clientes especiais.

Clique no link abaixo para resgatar seu prêmio:
https://promocoes-gratis.top/resgate/confirmar

Oferta válida por apenas 24 horas!
```

**Características de Spam:**
- ❌ Remetente não confiável (domínio suspeito: .top)
- ❌ Tom de urgência e pressa
- ❌ Oferta irrealista
- ❌ Link com redirecionamento suspeito
- ❌ Sem identificação clara da empresa
- ❌ Falta de opção de cancelamento/cadastro

**Ação correta:**
- Marcar como spam
- Não clicar em links
- Não responder
- Bloquear remetente

---

## ⚖️ Legislação e Regulamentação

| País/Região | Lei | Descrição |
|-------------|-----|-----------|
| **Brasil** | Lei 7.737/2022 (Lei do Spam) | Obriga opt-in para envio de mensagens comerciais; multa para quem descumprir |
| **Brasil** | Marco Civil da Internet (12.965/2014) | Princípios para neutralidade, privacidade e responsabilidade de provedores |
| **Brasil** | LGPD (13.709/2018) | Uso de dados pessoais para marketing requer consentimento explícito |
| **EUA** | CAN-SPAM Act (2003) | Exige identificação clara, remetente válido, e opt-out funcional |
| **União Europeia** | GDPR (2018) | Opt-in obrigatório, direito de esquecimento, penalidades severas |
| **União Europeia** | ePrivacy Directive | Regulamenta comunicações eletrônicas não solicitadas |
| **Canadá** | CASL (2014) | Uma das leis anti-spam mais rigorosas do mundo |
| **Austrália** | Spam Act 2003 | Proíbe spam comercial e permite multas pesadas |

---

## 🔬 Técnicas Avançadas de Spam

### ✅ **Técnicas de Evasão**

| Técnica | Descrição |
|---------|-----------|
| **Word Obfuscation** | Substituição de letras por caracteres especiais (ex: V1@gr4) |
| **Image Spam** | Texto da mensagem em imagem, bypass de filtros de texto |
| **URL Shorteners** | Uso de encurtadores para esconder destino malicioso |
| **IP Rotation** | Mudança constante de IP para evitar blacklists |
| **Snowshoe Spam** | Envio de baixo volume por muitos IPs diferentes |
| **Spam in Parts** | Dividir mensagem em partes para evitar detecção |
| **Time-based Sending** | Enviar em horários de menor atividade de filtros |
| **Multipart Spam** | Várias camadas de codificação para esconder conteúdo |

### ✅ **Infraestrutura de Spam**

| Componente | Função |
|------------|--------|
| **Botnets** | Dispositivos infectados usados como servidores de envio |
| **Open Relays** | Servidores SMTP configurados incorretamente |
| **Spam Bulletins** | Fornecimento de alvos de e-mail comprados/coletados |
| **Affiliate Networks** | Redes de promoção para produtos fraudulentos |
| **Fast-Flux Networks** | Mudança rápida de IP para evasão |
| **Domain Generation Algorithms (DGA)** | Geração automática de domínios para evitar bloqueios |
| **Bulletproof Hosting** | Servidores em países com legislação permissiva |

---

## 📊 Anatomia de um Spam

```
┌────────────────────────────────────────────────────┐
│  HEADER                                            │
│  From: "Banco Falso" <falso@email.fake>            │
│  Subject: ALERTA DE SEGURANÇA! Conta bloqueada     │
│  Received: from 185.xxx.xxx.xxx (spam-server.top)  │
├────────────────────────────────────────────────────┤
│  BODY                                              │
│  Prezado cliente,                                  │
│  Detectamos atividade suspeita em sua conta...     │
│  Clique aqui para verificar: [LINK MALICIOSO]      │
│  Caso não aja em 24h, sua conta será cancelada.    │
├────────────────────────────────────────────────────┤
│  FOOTER                                            │
│  © 2024 Banco Falso. Todos os direitos reservados. │
│  Para cancelar, clique aqui: [LINK DE OPT-OUT]     │
└────────────────────────────────────────────────────┘
```

---

## 🎯 Táticas de Engajamento em Spam

| Tática | Descrição | Exemplo |
|--------|-----------|---------|
| **FOMO** | Medo de perder algo | "Últimas vagas!" |
| **Urgência** | Tempo limitado | "Oferta válida apenas hoje!" |
| **Autoridade** | Citação de especialistas | "Recomendado por 10 médicos" |
| **Reciprocidade** | Algo em troca | "Ganhe brindes exclusivos" |
| **Social Proof** | "Milhares já compraram" | "Mais de 50.000 clientes" |
| **Escassez** | Produto limitado | "Apenas 5 unidades restantes!" |
| **Curiosidade** | Mistério no assunto | "Você não vai acreditar..." |
| **Personalização** | Uso de nome | "Olá, João..." (coletado por scraping) |

---

## 📈 Tendências Emergentes

| Tendência | Descrição |
|-----------|-----------|
| **Spam com IA** | Conteúdo gerado por IA, mais convincente e personalizado |
| **Spam via VoIP** | Robocalls com mensagens gravadas |
| **Spam em RCS/WhatsApp** | Mensagens ricas com links clicáveis |
| **Deepfake Spam** | Mensagens com vozes e vídeos falsificados |
| **Spam como Serviço** | Infraestrutura de spam comercializada na dark web |
| **Spam Multi-canal** | Coordenação entre e-mail, SMS, redes sociais |
| **Spam de Verificação 2FA** | Falsas tentativas de verificação de segurança |

---

## 📋 Checklist de Segurança Anti-Spam

### ✅ **Para Usuários**
- [ ] Usar diferentes e-mails: pessoal, profissional, cadastro
- [ ] Ativar filtro anti-spam do provedor
- [ ] Não clicar em links de e-mails não solicitados
- [ ] Verificar remetente antes de interagir
- [ ] Reportar spam para o serviço de e-mail
- [ ] Não abrir anexos de fontes desconhecidas
- [ ] Desconfiar de ofertas muito boas para serem verdade

### ✅ **Para Empresas**
- [ ] Implementar SPF, DKIM, DMARC
- [ ] Usar gateway anti-spam empresarial
- [ ] Treinar funcionários sobre spam
- [ ] Monitorar listas negras de IPs
- [ ] Política de opt-in e opt-out clara
- [ ] Revisar relatórios de spam diariamente
- [ ] Manter software de e-mail atualizado
- [ ] Bloquear anexos perigosos (exe, scr, vbs)

---

## 🔗 Referências e Links Úteis

- [Spamhaus - Listas de bloqueio](https://www.spamhaus.org/)
- [M3AAWG - Anti-Spam Guidelines](https://www.m3aawg.org/)
- [CERT.br - Cartilha de Spam](https://cartilha.cert.br/)
- [Google Postmaster Tools](https://postmaster.google.com/)
- [Sender Score](https://www.senderscore.org/)
- [DMARC.org](https://dmarc.org/)
- [Microsoft Spam Filtering](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/)

---

> ⚠️ **Nota**: O spam continua sendo um dos principais vetores para ataques cibernéticos, incluindo phishing, ransomware e fraude financeira. A conscientização e o treinamento contínuo são as defesas mais eficazes. Nunca confie em mensagens não solicitadas, mesmo que pareçam legítimas.

---

## 📊 Matriz de Avaliação de Risco de Spam

| Critério | Baixo Risco | Médio Risco | Alto Risco |
|----------|-------------|-------------|------------|
| **Remetente** | Domínio conhecido com SPF/DKIM | Domínio desconhecido mas funcional | Domínio recente, genérico ou com erros |
| **Conteúdo** | Mensagem relevante e solicitada | Oferta moderada com opt-out | Urgência, ameaças, gramática ruim |
| **Anexos** | Nenhum ou .pdf/.docx esperado | .exe/.scr/.zip com senha | .js/.vbs/.com executáveis |
| **Links** | Domínio conhecido e HTTPS | Domínio encurtado desconhecido | Domínio não relacionado ao remetente |
| **Solicitação** | Nenhum dado pessoal | Solicita e-mail ou nome | Solicita senha, CPF, dados bancários |
| **Ação Recomendada** | Manter monitoramento | Verificar antes de interagir | Marcar como spam e bloquear |

# Physical Attacks (Ataques Físicos)

## 📌 Definição

Ataques físicos são tentativas de comprometer a segurança de sistemas, dados ou infraestrutura por meio de acesso físico direto a dispositivos, instalações ou equipamentos. Diferentemente de ataques puramente digitais, estes exploram a interface entre o mundo físico e o cibernético, muitas vezes contornando controles de segurança cibernética sofisticados ao atacar o "elo mais fraco" – o ambiente físico onde os sistemas estão hospedados.

---

## 🧠 Como Funciona

O ataque físico geralmente segue estas etapas:

1. **Reconhecimento Físico**: O atacante estuda o local, horários, rotinas, pontos de entrada e segurança perimetral.
2. **Planejamento**: Define a melhor abordagem (entrada forçada, engenharia social, dispositivo oculto, etc.).
3. **Execução**: Obtém acesso físico ao alvo e realiza a ação pretendida.
4. **Exfiltração/Saída**: Remove dados ou dispositivos e deixa o local sem levantar suspeitas.
5. **Pós-exploração**: Utiliza o acesso ou dados obtidos para atingir o objetivo final.

---

## 🧩 Tipos de Ataques Físicos

| Categoria | Descrição | Subcategorias |
|-----------|-----------|---------------|
| **Acesso Não Autorizado** | Entrada física em áreas restritas | - Tailgating/Piggybacking<br>- Destruição de fechaduras<br>- Clonagem de cartões de acesso<br>- Escalada de perímetro |
| **Ataques a Hardware** | Manipulação direta de dispositivos físicos | - Inserção de keyloggers<br>- Computadores roubados<br>- Dispositivos USB maliciosos<br>- Ataques a portas I/O |
| **Engenharia Social Física** | Manipulação psicológica para obter acesso | - Falsificação de identidade<br>- Phishing presencial<br>- Pretexting<br>- Baiting físico |
| **Ataques de Side-Channel** | Exploração de emissões físicas do dispositivo | - Análise de consumo de energia<br>- Emissões eletromagnéticas<br>- Análise de tempo<br>- Sons/acústica (acoustic cryptanalysis) |
| **Coleta de Lixo** | Obtenção de informações de resíduos descartados | - Papelada (dumpster diving)<br>- Discos rígidos descartados<br>- Dispositivos eletrônicos obsoletos |
| **Ataques de Temperatura/Física** | Danos ou manipulação por condições extremas | - Ataques de congelamento<br>- Overclocking<br>- Injeção de falhas (fault injection) |

---

## 📊 Casos Reais Notórios

### 1. **Stuxnet (2010)**
- **Impacto**: Destruiu centrífugas nucleares iranianas.
- **Mecanismo**: Provavelmente introduzido via USB físico por um insider.
- **Importância**: Demonstrou que ataques digitais podem ter consequências físicas devastadoras.

### 2. **Edward Snowden (2013)**
- **Impacto**: Vazamento de milhões de documentos da NSA.
- **Mecanismo**: Acesso físico a servidores e sistemas internos.
- **Revelação**: A segurança física interna era tão crítica quanto a cibernética.

### 3. **Roubo de Laptops da Equifax (2017)**
- **Impacto**: Dados sensíveis de 147 milhões de pessoas expostos.
- **Mecanismo**: Laptops não criptografados roubados de funcionários.
- **Lição**: Dispositivos móveis são pontos vulneráveis críticos.

### 4. **Ataque à Malásia (2009)**
- **Impacto**: Roubo de US$ 40 milhões de caixas eletrônicos.
- **Mecanismo**: Instalação de skimmers e câmeras em ATMs.
- **Técnica**: Clonagem de cartões combinada com captura de PIN.

---

## 🛡️ Como se Proteger

### 🔒 **Controles de Acesso Físico**

- ✅ **Controle de entrada biométrico**: Impressão digital, íris, reconhecimento facial.
- ✅ **Câmeras de vigilância**: Cobertura de pontos críticos com monitoramento 24/7.
- ✅ **Sistemas de alarme**: Sensores de movimento, portas, janelas.
- ✅ **Barreiras físicas**: Portas reforçadas, grades, vidros blindados.
- ✅ **Registro de visitantes**: Controle rigoroso de acesso de terceiros.

### 💻 **Proteção de Hardware**

- ✅ **Criptografia de disco completo**: BitLocker, FileVault, LUKS.
- ✅ **Portas USB bloqueadas**: Software ou hardware para bloquear portas não autorizadas.
- ✅ **Computadores com TPM**: Trusted Platform Module para segurança de hardware.
- ✅ **Selos de integridade**: Lacres físicos para identificar violação.
- ✅ **Rastreamento de ativos**: GPS e gerenciamento de dispositivos móveis (MDM).

### 👥 **Políticas e Procedimentos**

- ✅ **Treinamento de funcionários**: Conscientização sobre engenharia social presencial.
- ✅ **Política de área limpa**: "Clean desk" e descarte seguro de documentos.
- ✅ **Procedimentos de descarte seguro**: Destruição de HDs, documentos confidenciais.
- ✅ **Auditoria de acesso**: Revisão regular de logs de entrada/saída.
- ✅ **Regra de escolta**: Visitantes devem ser acompanhados por funcionários.

---

## 🧰 Ferramentas de Defesa Física

| Categoria | Ferramentas | Uso |
|-----------|-------------|-----|
| **Controle de Acesso** | Smart cards, Biometria, RFID | Autenticação física |
| **Vigilância** | Câmeras IP, NVR, DVR | Monitoramento de áreas |
| **Detecção** | Sensores magnéticos, Infravermelho, Micro-ondas | Detecção de intrusão |
| **Prevenção** | Portas giratórias, Catracas, Mantas Faraday | Barreiras físicas e anti-escuta |
| **Destruição de Dados** | Trituradores, Degaussers, Destruidores de HDs | Eliminação segura |
| **Verificação de Hardware** | Analisadores de espectro, Osciloscópios | Detecção de dispositivos ocultos |

---

## 📈 Estatísticas Relevantes

- **50%** dos ataques físicos são realizados por funcionários internos (SANS Institute).
- **35%** dos incidentes de segurança física começam com engenharia social.
- **25%** das empresas não possuem política de descarte seguro para equipamentos.
- **80%** das violações de dados poderiam ser evitadas com melhor segurança física (Verizon).
- **$100** por funcionário/mês é o custo médio para implementar segurança física robusta.

---

## 🎯 Principais Vetores de Ataque

| Vetor | Descrição | Probabilidade |
|-------|-----------|---------------|
| **Tailgating** | Acompanhante não autorizado entra atrás de funcionário legítimo | Alta |
| **USB Drop** | Pendrives infectados deixados propositalmente em estacionamentos | Média |
| **Shoulder Surfing** | Observação de senhas digitadas em teclados ou telas | Alta |
| **Skimming** | Dispositivos sobrepostos em ATMs ou leitores de cartão | Média |
| **Dumpster Diving** | Busca em lixo por documentos confidenciais | Média |
| **Impersonation** | Fingir ser funcionário, entregador, técnico de manutenção | Alta |
| **Lock Picking** | Arrombamento de fechaduras físicas | Baixa/Média |
| **Bypass de sensores** | Neutralização de alarmes e sensores de movimento | Baixa |

---

## 📘 Exemplo Prático: Ataque de USB Drop

**Cenário**: Atacante deixa pendrive infectado no estacionamento de uma empresa.

```
1. Funcionário encontra pendrive no estacionamento
2. Curioso, conecta ao computador para ver o conteúdo
3. Pendrive está configurado como "Teclado USB" (HID)
4. Executa automaticamente comandos maliciosos
5. Baixa e instala backdoor
6. Atacante ganha acesso remoto à rede corporativa
7. Sistema comprometido é usado como pivô para outros ataques
```

**Como prevenir**:
- ✅ Política de "Nunca conecte dispositivos USB desconhecidos"
- ✅ Bloquear portas USB em estações de trabalho
- ✅ Treinamento frequente sobre riscos de dispositivos externos
- ✅ Implementar endpoint protection com detecção HID

---

## 🔬 Técnicas Avançadas

### ✅ **Ataques de Side-Channel**

| Técnica | Descrição |
|---------|-----------|
| **Power Analysis** | Análise de variações de consumo de energia para extrair chaves criptográficas |
| **EM Side-Channel** | Captura de emissões eletromagnéticas (TEMPEST) de monitores, cabos, teclados |
| **Timing Analysis** | Medição de tempo de operações para deduzir informações sensíveis |
| **Acoustic Cryptanalysis** | Análise de sons emitidos por componentes (fans, capacitores) |
| **Thermal Imaging** | Imagens térmicas de teclados para descobrir senhas digitadas recentemente |

### ✅ **Ataques de Injeção de Falhas**

| Técnica | Descrição |
|---------|-----------|
| **Voltage Glitching** | Quedas de voltagem para corromper operações do processador |
| **Clock Glitching** | Manipulação do clock para causar erros computacionais |
| **Electromagnetic Fault Injection** | Uso de campos eletromagnéticos para induzir falhas |
| **Laser Fault Injection** | Lasers para causar falhas localizadas em chips |
| **Temperature Manipulation** | Resfriamento extremo para preservar dados em RAM (Cold Boot) |

---

## 🏢 Segurança por Camadas

```
┌─────────────────────────────────────────────┐
│        Camada 1: Perímetro Físico           │
│  Muros, cercas, portões, iluminação         │
├─────────────────────────────────────────────┤
│        Camada 2: Controle de Acesso         │
│  Catracas, crachás, biometria, guardas      │
├─────────────────────────────────────────────┤
│        Camada 3: Monitoramento              │
│  Câmeras, sensores de movimento, alarmes    │
├─────────────────────────────────────────────┤
│        Camada 4: Segurança do Hardware      │
│  TPM, criptografia, bloqueio de portas      │
├─────────────────────────────────────────────┤
│        Camada 5: Segurança do Software      │
│  Autenticação, criptografia, endpoint       │
├─────────────────────────────────────────────┤
│        Camada 6: Fator Humano               │
│  Treinamento, políticas, conscientização    │
└─────────────────────────────────────────────┘
```

---

## 📋 Checklist de Segurança Física

### ✅ **Instalações**
- [ ] Controle de acesso para todas as entradas e saídas
- [ ] Câmeras de vigilância em pontos estratégicos
- [ ] Sensores de movimento e alarmes em áreas restritas
- [ ] Portas resistentes com fechaduras de alta segurança
- [ ] Sistema de backup de energia e climatização

### ✅ **Equipamentos**
- [ ] Criptografia de disco em todos os dispositivos móveis
- [ ] Bloqueio de portas USB em estações críticas
- [ ] Rastreamento de ativos via GPS/MDM
- [ ] Selos de integridade em gabinetes de servidores
- [ ] Destruição segura de mídias obsoletas

### ✅ **Pessoas**
- [ ] Treinamento contra engenharia social presencial
- [ ] Política de visitantes e acompanhamento
- [ ] Procedimentos para incidentes de segurança física
- [ ] Verificação de antecedentes de funcionários
- [ ] Política de "Clean Desk" e "Clear Screen"

### ✅ **Procedimentos**
- [ ] Auditoria regular de acesso físico
- [ ] Registro de entrada/saída de pessoas e materiais
- [ ] Plano de resposta a incidentes físicos
- [ ] Testes periódicos de penetração física
- [ ] Revisão de políticas de segurança física

---

## 🔗 Padrões e Regulamentações

| Padrão | Descrição |
|--------|-----------|
| **ISO/IEC 27001** | Controles de segurança da informação (Anexo A.11 - Segurança Física e Ambiental) |
| **PCI DSS** | Requisitos para segurança de dados de cartão (Controles físicos para dados de pagamento) |
| **HIPAA** | Segurança de dados de saúde (Controles físicos em instalações de saúde) |
| **NIST SP 800-53** | Controles de segurança física para sistemas federais dos EUA |
| **FISMA** | Requisitos de segurança para agências governamentais |
| **SOX** | Auditoria de controles internos, incluindo acesso físico a sistemas financeiros |

---

## 🔗 Referências e Links Úteis

- [NIST - Physical Security Guidelines](https://www.nist.gov/)
- [ASIS International - Security Standards](https://www.asisonline.org/)
- [SANS - Physical Security Resources](https://www.sans.org/security-resources/)
- [CISA - Physical Security](https://www.cisa.gov/physical-security)
- [FBI - Physical Security Standards](https://www.fbi.gov/)
- [NATO - Physical Security Guide](https://www.nato.int/)

---

> ⚠️ **Nota**: Segurança física é frequentemente negligenciada em favor de medidas cibernéticas, mas representa uma camada crítica de defesa. Muitos ataques cibernéticos bem-sucedidos começam com uma brecha na segurança física. Invista em treinamento, infraestrutura e conscientização em todos os níveis da organização.

---

## 📊 Matriz de Risco Físico

| Probabilidade | Impacto Baixo | Impacto Médio | Impacto Alto |
|---------------|---------------|---------------|--------------|
| **Alta** | Perda de laptop (criptografado) | Roubo de servidor com dados sensíveis | Acesso a datacenter com backups críticos |
| **Média** | Furto de equipamentos periféricos | Destruição de documentação física | Instalação de dispositivos de escuta |
| **Baixa** | Quebra de câmeras de vigilância | Ataque de side-channel em área restrita | Ataque de injeção de falhas em hardware crítico |

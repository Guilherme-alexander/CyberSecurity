# SayCheese – Captura Remota de Fotos via Link Malicioso

### Visão Geral

O **SayCheese** é uma ferramenta de teste de penetração desenvolvida para demonstrar como um atacante pode capturar remotamente fotografias por meio de um link malicioso. Este projeto tem caráter estritamente educacional, com o objetivo de ilustrar os aspectos técnicos desse tipo de ataque, permitindo que profissionais de segurança implementem contramedidas eficazes.

Os principais objetivos desta demonstração são:
- Evidenciar a importância de configurar regras de proxy e firewall para bloquear serviços de tunelamento
- Reforçar as campanhas de conscientização em segurança, prevenindo que colaboradores cliquem em links não solicitados recebidos por e-mail, redes sociais ou aplicativos de mensagem

> **Atenção:** Esta ferramenta destina-se exclusivamente a testes de segurança autorizados e fins educacionais. O uso não autorizado pode violar leis e regulamentações aplicáveis.

Com base no conceito do SayCheese, desenvolvemos também o **SayHello** – uma versão aprimorada com funcionalidades adicionais. Para mais detalhes, acesse o artigo [SayHello](www.100security.com.br/sayhello).

---

## Guia de Teste Passo a Passo

### 1. Iniciar o Serviço Apache2

Para permitir a visualização das imagens por meio do navegador, inicie o serviço Apache2 utilizando um dos seguintes comandos:

```bash
./etc/init.d/apache2 start
```

ou

```bash
systemctl start apache2
```

ou ainda

```bash
service apache2 start
```

![Inicialização do Apache2](https://www.100security.com.br/images/saycheese-01.png)

---

### 2. Baixar e Configurar o SayCheese

Navegue até o diretório web do Apache, faça o clone do repositório SayCheese a partir do GitHub e atribua as permissões de execução necessárias:

```bash
cd /var/www/html/
git clone https://github.com/hangetzzu/saycheese
cd saycheese/
chmod +x *
ls -l
```

![Configuração do Repositório](https://www.100security.com.br/images/saycheese-02.png)

---

### 3. Executar o Script Principal

Execute o script `saycheese.sh`. Você será solicitado a selecionar um serviço de tunelamento para gerar uma URL pública de acesso:

```
[ 01 ] Serveo.net
[ 02 ] Ngrok
```

```bash
./saycheese.sh
```

Após a seleção, um link publicamente acessível será gerado automaticamente.

![Execução do Script](https://www.100security.com.br/images/saycheese-03.png)

---

### 4. Distribuir o Link para o Alvo

Assim que o usuário alvo acessar a URL gerada, a ferramenta iniciará a captura contínua de fotos por meio da câmera do dispositivo, desde que as permissões necessárias sejam concedidas.

![Confirmação de Acesso](https://www.100security.com.br/images/saycheese-04.png)

O console exibirá:
- O endereço IP do alvo que está acessando o link
- Uma mensagem de confirmação sempre que uma foto for capturada com sucesso

![Registro de Captura](https://www.100security.com.br/images/saycheese-05.png)

---

### 5. Organizar as Imagens Capturadas

Para manter as imagens organizadas, crie um diretório dedicado e mova todos os arquivos com extensão `.png` para dentro dele:

```bash
mkdir fotos
mv *.png fotos/
cd fotos/
ls -l
```

![Organização das Imagens](https://www.100security.com.br/images/saycheese-06.png)

Em seguida, acesse as imagens via navegador, navegando até a URL local correspondente, e selecione qualquer arquivo para visualização.

![Visualização da Galeria](https://www.100security.com.br/images/saycheese-07.png)

---

## Recomendações de Segurança

Para proteger sua organização contra ataques semelhantes, considere as seguintes medidas:

- **Bloquear Serviços de Tunelamento:** Configure regras no proxy e no firewall para restringir o uso de serviços de tunelamento conhecidos, como Serveo e Ngrok.
- **Treinamento de Conscientização:** Eduque os colaboradores sobre os riscos de clicar em links desconhecidos ou não solicitados, independentemente do canal de entrega (e-mail, aplicativos de mensagem, redes sociais).
- **Políticas de Segurança no Navegador:** Implemente políticas que restrinjam o acesso à câmera e ao microfone por padrão, exigindo consentimento explícito do usuário.
- **Monitoramento de Rede:** Mantenha um monitoramento ativo para detectar tentativas de exfiltração de dados ou comportamentos anômalos relacionados a serviços de tunelamento.

---

## Aviso Legal

Esta ferramenta e sua documentação são fornecidas **exclusivamente para fins educacionais e testes de segurança autorizados**. Os autores não se responsabilizam por qualquer uso indevido ou atividades ilegais realizadas com este software. Certifique-se sempre de obter a devida autorização antes de testar qualquer sistema.

---

### Autor: Marcos Henrique
Perfil: <a href="https://www.100security.com.br/marcos-henrique">Web Site Marcos henrique</a>

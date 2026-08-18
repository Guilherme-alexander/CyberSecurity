# ByPass

O Microsoft SmartScreen é uma tecnologia de filtragem desenvolvida pela Microsoft que é usada para identificar sites suspeitos e bloquear o acesso a eles, ajudar a prevenir phishing e filtrar downloads de software potencialmente perigosos.

## Como o SmartScreen funciona
O SmartScreen mantém uma lista atualizada em tempo real de sites e arquivos maliciosos. Ele faz isso através de:

- Consultas em nuvem: Cada download ou site acessado é verificado com os servidores da Microsoft/Google.
- Reputação: Arquivos pouco conhecidos são bloqueados automaticamente.
- Heurística: Comportamentos suspeitos são detectados mesmo sem assinatura de vírus.

### Google Chrome
Observe que ao ser realizado o download o SmartScreen entra em ação bloqueando o download.

### Microsoft Edge
Neste caso o site ja é classificado como um site não seguro

### Mozilla Firefox
O download também é bloqueado

## ByPass
Para realizar o **ByPass**, basta acessar o arquivo **hosts** como **Administrador** e direcionar os endereços abaixo para o **IP** ex: `0.0.0.0`

### O que o bypass no hosts faz
O arquivo hosts é um resolvedor local de DNS que tem prioridade sobre os servidores DNS da internet.

### Quando você adiciona:

```txt
# SmartScreen
0.0.0.0	telem-edge.smartscreen.microsoft.com dl-edge.smartscreen.microsoft.com nav-edge.smartscreen.microsoft.com safebrowsing.googleapis.com safebrowsing-cache.google.com safebrowsing.google.com sb-ssl.google.com app-edge.smartscreen.microsoft.com
```

Você está dizendo ao sistema: Não consulte o DNS externo para esse domínio. Simplesmente redirecione para 0.0.0.0 (um IP que não leva a lugar nenhum)

## **Arquivo**: C:\Windows\System32\drivers\etc\hosts

<img width="1122" height="683" alt="image" src="https://github.com/user-attachments/assets/b61e695d-8cc2-49b4-976a-9580ca8a6cb0" />

>Resultado: O navegador tenta contatar os servidores de verificação, mas não consegue. Ele interpreta isso como "servidor indisponível" e permite o download por falha de comunicação, assumindo que você está offline ou que o serviço está temporariamente fora do ar.

### Com o bypass (VULNERÁVEL): Google Chrome | Microsoft Edge | Mozilla Firefox
Não é exibido nenhum bloqueio do download.

```txt
Usuário tenta baixar arquivo.exe
         ↓
Navegador consulta SmartScreen → 0.0.0.0 (sem resposta)
         ↓
Timeout → "Servidor indisponível"
         ↓
Download PERMITIDO ❌ (mesmo que seja vírus)
```

### Observação
Este procedimento compromete a segurança do sistema operacional tornando-o vulnerável a qualquer tipo de ameaça caso não possua nenhuma proteção adicional.

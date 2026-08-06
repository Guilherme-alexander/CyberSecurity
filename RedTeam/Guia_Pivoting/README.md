# README.md - Guia de Estudos sobre Pivoting

Bem-vindo ao guia definitivo sobre pivoting para Red Teamers. Este repositório foi criado para documentar, de forma clara e prática, os conceitos, técnicas e fluxos de trabalho essenciais para quem deseja dominar a arte de se mover lateralmente em redes durante testes de invasão e simulações de adversários.

## 📖 Sobre o Projeto

Este projeto reúne três guias complementares sobre pivoting, cobrindo desde os fundamentos teóricos até a aplicação prática em cenários reais.

### A História do Pivoting: Como Surgiu?

O conceito de "pivoting" no contexto de segurança cibernética é emprestado do basquete, onde um jogador mantém um pé fixo no chão (o sistema comprometido) enquanto gira para encontrar uma nova posição de ataque (movimento lateral).

Na segurança da informação, a técnica surgiu naturalmente com a evolução dos testes de penetração. À medida que as redes se tornaram mais complexas e segmentadas, os profissionais de segurança perceberam que, após comprometer um único host, precisavam de métodos para acessar outras partes da rede que não eram diretamente acessíveis.

Os primeiros relatos documentados do uso de "pivoting" como termo técnico remontam ao início dos anos 2000, com a popularização de ferramentas como o **Netcat** (o "canivete suíço" das redes) e o **SSH Port Forwarding**, que já permitiam o redirecionamento de tráfego. No entanto, foi com o advento de frameworks de pós-exploração como o **Metasploit Project** (lançado em 2003) e, mais tarde, com ferramentas especializadas como **ProxyChains** e **Socat**, que a técnica foi sistematizada e se tornou uma habilidade fundamental para equipes de Red Team.

Hoje, o pivoting é uma competência essencial, com técnicas que vão desde o simples encaminhamento de portas até túneis complexos sobre DNS e ICMP, como documentado neste guia.

## 📁 Estrutura do Repositório

O repositório está organizado nos seguintes arquivos:

1.  **`lab.md`**
    - **Descrição**: Um guia prático para configurar um ambiente de laboratório para testar as técnicas de pivoting.
    - **Conteúdo**: Instruções passo a passo, topologia de rede sugerida, e exemplos de uso de ferramentas como `msfvenom` e `Meterpreter` para criar e encadear ataques.

2.  **`pivoting.md`**
    - **Descrição**: O guia conceitual principal.
    - **Conteúdo**: Explica o que é pivoting, para que serve, o fluxo de funcionamento, as camadas de rede e protocolos envolvidos, e apresenta diagramas de arquitetura para diferentes cenários (NAT, Proxy Corporativo, etc.).

3.  **`Guia-Completo-de-Pivoting.md`**
    - **Descrição**: Um manual técnico com exemplos práticos de comandos e ferramentas.
    - **Conteúdo**: Detalha técnicas como SSH Local/Remote Port Forwarding, túneis SOCKS, VPN sobre SSH, DNS/ICMP Tunneling com ferramentas como `iodine`, `dnscat2` e `hans`, e uso de `proxychains`.

## 🚀 Como Utilizar Este Guia

1.  **Comece pelo `pivoting.md`** para entender os conceitos fundamentais e a arquitetura por trás das técnicas.
2.  Em seguida, **leia o `Guia-Completo-de-Pivoting.md`** para ver exemplos práticos de como cada técnica é aplicada, com comandos e ferramentas.
3.  **Finalize com o `lab.md`** para colocar a mão na massa. Configure o laboratório sugerido e pratique os ataques em um ambiente controlado.

## 🤝 Contribuições

Este é um projeto em constante evolução. Se você tem sugestões, correções ou novos exemplos que gostaria de compartilhar, sinta-se à vontade para abrir uma *issue* ou enviar um *pull request*.

## 📚 Referências e Estudos Recomendados

Para aprofundar seus conhecimentos, recomendamos os seguintes recursos:

*   **Documentação Oficial das Ferramentas**:
    *   [ProxyChains](https://github.com/haad/proxychains)
    *   [Metasploit Framework](https://www.metasploit.com/)
    *   [Socat](http://www.dest-unreach.org/socat/)
*   **Artigos Técnicos e Guias**:
    *   *Red Team Pivoting Techniques* - (Busque por este termo em plataformas como Medium ou blogs de segurança)
    *   *A Guide to Port Forwarding and Tunneling* - (Artigos clássicos sobre SSH)
*   **Cursos e Certificações**:
    *   Certificações como OSCP (Offensive Security Certified Professional) e CRTP (Certified Red Team Professional) cobrem extensivamente técnicas de pivoting.

---

**Aviso Legal:** Todo o conteúdo deste repositório é fornecido para fins educacionais e de estudo. A aplicação destas técnicas em sistemas sem autorização prévia é ilegal e antiética. Utilize este conhecimento de forma responsável.

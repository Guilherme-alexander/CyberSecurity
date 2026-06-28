# ASSEMBLY

```bash
|           ______      __              _____                      _ __
|          / ____/_  __/ /_  ___  _____/ ___/___  _______  _______(_) /___  __
|         / /   / / / / __ \/ _ \/ ___/\__ \/ _ \/ ___/ / / / ___/ / __/ / / /
|        / /___/ /_/ / /_/ /  __/ /   ___/ /  __/ /__/ /_/ / /  / / /_/ /_/ /
|        \____/\__, /_.___/\___/_/   /____/\___/\___/\__,_/_/  /_/\__/\__, /
|              /____/                                                /____/ 
|
| ${ASSEMBLY}
```

## Assembly Studies
Repositório dedicado aos meus estudos de Assembly, arquitetura de computadores, Windows Internals e Linux Internals.

Essa é uma ótima seção para colocar no `README.md`, pois ajuda a contextualizar por que o Assembly existe. Na verdade, **não existe um único "criador do Assembly"**. A linguagem Assembly surgiu como consequência da evolução dos primeiros computadores.

<br/>

# História do Assembly

## O nascimento da programação

Nos primeiros computadores, durante as décadas de **1940 e início dos anos 1950**, não existiam linguagens de programação.

Os programas eram escritos diretamente em **código de máquina**, utilizando apenas números binários (0 e 1).

Exemplo:

```text
10110000 01100001
```

ou

```text
11001000 00010010
```

Programar dessa forma era extremamente difícil, pois cada sequência de bits correspondia a uma instrução específica do processador.

<br/>

## O problema

Imagine escrever milhares de linhas assim:

```text
10001011
01000101
11111100
```

Era praticamente impossível memorizar o significado de cada instrução, tornando o desenvolvimento lento e sujeito a muitos erros.

<br/>

# O surgimento do Assembly

Para facilitar a programação, pesquisadores começaram a substituir os códigos binários por **palavras simbólicas (mnemônicos)**.

Em vez de escrever:

```text
10110000
```

escrevia-se:

```asm
MOV
```

Em vez de:

```text
00000001
```

escrevia-se:

```asm
ADD
```

Assim nasceu a linguagem **Assembly**.

<br/>

# Quem criou?

Não existe um único inventor do Assembly.

A ideia surgiu coletivamente no início da década de 1950, principalmente em universidades e laboratórios de pesquisa que trabalhavam com os primeiros computadores eletrônicos.

Um dos principais nomes associados a essa evolução é a Kathleen Booth.

Em **1947**, ela desenvolveu uma linguagem baseada em notação simbólica para o computador ARC2, considerada por muitos historiadores uma das primeiras linguagens Assembly da história.

<br/>

## Kathleen Booth

Kathleen Booth foi uma matemática e cientista da computação britânica cuja carreira ajudou a moldar os primeiros anos da computação moderna. Ela é amplamente reconhecida por criar uma das primeiras linguagens de montagem (assembly language) e por suas contribuições fundamentais ao desenvolvimento de computadores, programação e tradução automática, embora seu trabalho tenha recebido reconhecimento mais amplo apenas décadas depois.

### Principais contribuições

Kathleen Booth trabalhou no Birkbeck College a partir de 1946, colaborando estreitamente com Andrew Booth no projeto de alguns dos primeiros computadores eletrônicos britânicos. Entre suas realizações mais importantes estão a criação de uma das primeiras linguagens assembly, o desenvolvimento de um montador (assembler) para esses sistemas e a autoria de um dos primeiros livros dedicados à programação, Programming for an Automatic Digital Calculator (1958).

### Legado
Durante muitos anos, parte de suas contribuições ficou ofuscada pelas dinâmicas colaborativas da época e pela maior visibilidade de colegas homens. Desde a década de 2010, historiadores da computação e instituições acadêmicas têm reavaliado sua importância, reconhecendo Kathleen Booth como uma das figuras essenciais na história da programação e da arquitetura dos primeiros computadores. Ela faleceu em 29 de setembro de 2022, aos 100 anos.

<br/>

# O primeiro Assembler

Depois que surgiram os mnemônicos, era necessário um programa que os convertesse novamente para código de máquina.

Esse programa recebeu o nome de **Assembler**.

Fluxo:

```text
Assembly
      │
      ▼
Assembler
      │
      ▼
Código de Máquina
      │
      ▼
CPU
```

<br/>

# Evolução

## Década de 1950

* Primeiros Assemblers
* Programação totalmente em Assembly
* Computadores ocupavam salas inteiras

<br/>

## Década de 1960

Surgiram diversas arquiteturas:

* IBM
* DEC
* CDC
* UNIVAC

Cada uma possuía seu próprio Assembly.

<br/>

## Década de 1970

Nasce o microprocessador.

Exemplos:

* Intel 4004
* Intel 8008
* Intel 8080
* MOS 6502
* Zilog Z80

O Assembly torna-se popular entre programadores.

<br/>

## Década de 1980

A Intel lança a família x86:

* 8086
* 80186
* 80286
* 80386
* 80486

Surge o Assembly x86.

<br/>

## Década de 1990

O Assembly passa a ser usado principalmente em:

* Sistemas Operacionais
* Drivers
* Jogos
* BIOS
* Bootloaders

<br/>

## Década de 2000

É lançada a arquitetura AMD64 (x86-64), trazendo:

* 64 bits
* Mais registradores
* Mais memória

<br/>

## Atualmente

Assembly continua sendo utilizado em:

* Desenvolvimento de kernels
* Drivers
* Sistemas embarcados
* Engenharia reversa
* Malware analysis
* Exploit Development
* Bootloaders
* Hypervisors
* Otimização de código
* Compiladores

<br/>

# Curiosidade

Uma característica importante é que **não existe uma única linguagem Assembly**.

Cada arquitetura possui sua própria linguagem Assembly.

| Arquitetura | Assembly         |
| ----------- | ---------------- |
| Intel x86   | x86 Assembly     |
| AMD64       | x64 Assembly     |
| ARM         | ARM Assembly     |
| ARM64       | AArch64 Assembly |
| MIPS        | MIPS Assembly    |
| RISC-V      | RISC-V Assembly  |
| PowerPC     | PowerPC Assembly |

Apesar das diferenças de sintaxe e instruções, todas têm o mesmo objetivo: fornecer uma representação simbólica das instruções que a CPU executa.

<br/>

# Linha do tempo

```text
1940 ─ Computadores programados em código de máquina
          │
1947 ─ Kathleen Booth cria uma linguagem simbólica para o ARC2
          │
1950 ─ Surgem os primeiros Assemblers
          │
1971 ─ Intel 4004
          │
1978 ─ Intel 8086
          │
1985 ─ Intel 80386 (32 bits)
          │
2003 ─ AMD64 (64 bits)
          │
Hoje ─ Assembly continua essencial em sistemas de baixo nível
```

### Esse texto serve muito bem como a seção de introdução do seu repositório, explicando de forma histórica o surgimento do Assembly antes de entrar nas arquiteturas específicas.

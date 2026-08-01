<div align="center">

# 🖥️ Assembly x86 — Referência de Instruções

**Uma referência profissional e orientada a exemplos para instruções assembly x86/x86-64.**

[![Linguagem](https://img.shields.io/badge/Linguagem-Assembly%20x86-blue?style=flat-square&logo=assemblyscript)](https://pt.wikipedia.org/wiki/Assembly)
[![Arquitetura](https://img.shields.io/badge/Arquitetura-x86%20%7C%20x86--64-orange?style=flat-square)](https://pt.wikipedia.org/wiki/X86-64)
[![Licença](https://img.shields.io/badge/Licen%C3%A7a-MIT-green?style=flat-square)](LICENSE)
[![Docs](https://img.shields.io/badge/Docs-69%20instru%C3%A7%C3%B5es-purple?style=flat-square)](.)

[🇺🇸 Read in English](./README.md)

</div>

---

## 📖 Sobre

Esta referência cobre **69 instruções x86/x86-64** organizadas em 10 categorias. Cada arquivo segue uma estrutura consistente:

- **Sintaxe** — notação exata do montador
- **Descrição** — o que a instrução faz e quando usá-la
- **Flags afetadas** — como o EFLAGS é modificado
- **Exemplos práticos** — padrões de código comentados e do mundo real
- **Observações** — armadilhas, dicas de desempenho e casos especiais
- **Veja também** — links cruzados para instruções relacionadas

Todos os exemplos usam **sintaxe Intel** (compatível com NASM/YASM) e têm como alvo o **modo 64 bits**, salvo indicação contrária.

---

## 📂 Estrutura de Diretórios

```
docs/
├── DataTransfer/       # Mover dados entre registradores e memória
│   ├── MOV.md          # Mover — a instrução mais fundamental
│   ├── LEA.md          # Carregar Endereço Efetivo — aritmética de ponteiros
│   ├── XCHG.md         # Trocar — swap atômico
│   ├── PUSH.md         # Empilhar na pilha
│   ├── POP.md          # Desempilhar da pilha
│   ├── MOVSX.md        # Mover com extensão de sinal (inteiros com sinal)
│   ├── MOVZX.md        # Mover com extensão de zero (inteiros sem sinal)
│   └── CMOV.md         # Mover condicional — seleção sem desvio
│
├── Arithmetic/         # Operações aritméticas inteiras
│   ├── ADD.md          # Adição
│   ├── SUB.md          # Subtração
│   ├── INC.md          # Incrementar em 1
│   ├── DEC.md          # Decrementar em 1
│   ├── MUL.md          # Multiplicação sem sinal
│   ├── IMUL.md         # Multiplicação com sinal (formas de 2/3 operandos)
│   ├── DIV.md          # Divisão sem sinal
│   ├── IDIV.md         # Divisão com sinal
│   └── NEG.md          # Negação em complemento de dois
│
├── Logic/              # Operações lógicas bit a bit
│   ├── AND.md          # E lógico — mascarar / limpar bits
│   ├── OR.md           # OU lógico — definir bits
│   ├── XOR.md          # XOR — alternar bits / zerar registrador
│   ├── NOT.md          # NOT lógico — complemento de um
│   └── TEST.md         # AND não destrutivo — verifica apenas flags
│
├── Compare/            # Comparação e definição condicional de byte
│   ├── CMP.md          # Comparar — subtração não destrutiva
│   ├── SETcc.md        # Definir byte por condição (bool sem desvio)
│   └── TEST.md         # → Veja Logic/TEST.md
│
├── Jump/               # Fluxo de controle — desvios e loops
│   ├── JMP.md          # Salto incondicional
│   ├── JE.md           # Saltar se Igual (ZF=1)
│   ├── JNE.md          # Saltar se Diferente (ZF=0)
│   ├── JL.md           # Saltar se Menor — com sinal
│   ├── JLE.md          # Saltar se Menor ou Igual — com sinal
│   ├── JG.md           # Saltar se Maior — com sinal
│   ├── JGE.md          # Saltar se Maior ou Igual — com sinal
│   ├── JC.md           # Saltar se Carry / Abaixo — sem sinal
│   ├── JNC.md          # Saltar se Sem Carry / Acima ou Igual
│   ├── JO.md           # Saltar se Overflow
│   └── LOOP.md         # Decrementar contador e repetir loop
│
├── Stack/              # Gerenciamento da pilha de chamadas
│   ├── PUSH.md         # → Veja DataTransfer/PUSH.md
│   ├── POP.md          # → Veja DataTransfer/POP.md
│   ├── CALL.md         # Chamar sub-rotina — empilha endereço de retorno
│   ├── RET.md          # Retornar de sub-rotina
│   ├── ENTER.md        # Criar frame de pilha (prólogo)
│   └── LEAVE.md        # Destruir frame de pilha (epílogo)
│
├── Shift/              # Deslocamento e rotação de bits
│   ├── SHL.md          # Deslocar à Esquerda Lógico (×2ⁿ)
│   ├── SHR.md          # Deslocar à Direita Lógico (÷2ⁿ sem sinal)
│   ├── SAR.md          # Deslocar à Direita Aritmético (÷2ⁿ com sinal)
│   ├── SAL.md          # Deslocar à Esquerda Aritmético (= SHL)
│   ├── ROL.md          # Rotacionar à Esquerda — bits circulam
│   ├── ROR.md          # Rotacionar à Direita — bits circulam
│   ├── RCL.md          # Rotacionar à Esquerda pelo Carry
│   └── RCR.md          # Rotacionar à Direita pelo Carry
│
├── String/             # Operações em massa de memória / strings
│   ├── MOVSB.md        # Mover Byte de String (memcpy)
│   ├── MOVSW.md        # Mover Word de String
│   ├── MOVSD.md        # Mover Doubleword de String
│   ├── STOS.md         # Armazenar String (memset)
│   ├── LODS.md         # Carregar String — iterar bytes
│   ├── SCAS.md         # Escanear String (memchr / strlen)
│   └── CMPS.md         # Comparar Strings (memcmp)
│
├── Flags/              # Manipulação direta de flags
│   ├── CLC.md          # Limpar Carry Flag
│   ├── STC.md          # Definir Carry Flag
│   ├── CLD.md          # Limpar Direction Flag (ops de string para frente)
│   ├── STD.md          # Definir Direction Flag (ops de string para trás)
│   ├── CLI.md          # Limpar Interrupt Flag — desabilitar IRQs (ring 0)
│   └── STI.md          # Definir Interrupt Flag — habilitar IRQs (ring 0)
│
└── Misc/               # Instruções de sistema e utilitárias
    ├── NOP.md          # Nenhuma Operação — alinhamento, patching
    ├── INT.md          # Interrupção de Software (breakpoint INT3, syscalls)
    ├── SYSCALL.md      # Chamada de sistema rápida 64 bits (Linux/macOS)
    ├── CPUID.md        # Detecção de recursos da CPU
    ├── RDTSC.md        # Ler contador de timestamp (benchmarking)
    └── HLT.md          # Parar processador (idle / desligamento do kernel)
```

---

## 🚀 Início Rápido

### Hello World — Linux x86-64 (NASM)

```asm
section .data
    msg db "Olá, Mundo!", 10
    len equ $ - msg

section .text
    global _start

_start:
    ; write(1, msg, len)
    mov rax, 1          ; syscall: sys_write
    mov rdi, 1          ; fd: saída padrão
    lea rsi, [msg]      ; ponteiro para o buffer
    mov rdx, len        ; quantidade de bytes
    syscall

    ; exit(0)
    mov rax, 60         ; syscall: sys_exit
    xor rdi, rdi        ; código de saída: 0
    syscall
```

```bash
nasm -f elf64 hello.asm -o hello.o
ld -o hello hello.o
./hello
```

---

## 📋 Índice de Instruções

### Transferência de Dados
| Instrução | Descrição |
|-----------|-----------|
| [MOV](DataTransfer/MOV.md) | Copiar valor entre registrador/memória |
| [LEA](DataTransfer/LEA.md) | Carregar endereço calculado (aritmética de ponteiros) |
| [XCHG](DataTransfer/XCHG.md) | Troca atômica de dois operandos |
| [PUSH](DataTransfer/PUSH.md) | Empilhar valor na pilha |
| [POP](DataTransfer/POP.md) | Desempilhar valor da pilha |
| [MOVSX](DataTransfer/MOVSX.md) | Mover com extensão de sinal (tipos com sinal) |
| [MOVZX](DataTransfer/MOVZX.md) | Mover com extensão de zero (tipos sem sinal) |
| [CMOV](DataTransfer/CMOV.md) | Mover condicional (seleção sem desvio) |

### Aritmética
| Instrução | Descrição |
|-----------|-----------|
| [ADD](Arithmetic/ADD.md) | Adição inteira |
| [SUB](Arithmetic/SUB.md) | Subtração inteira |
| [INC](Arithmetic/INC.md) | Incrementar em 1 (CF não afetada) |
| [DEC](Arithmetic/DEC.md) | Decrementar em 1 (CF não afetada) |
| [MUL](Arithmetic/MUL.md) | Multiplicação sem sinal (resultado amplo) |
| [IMUL](Arithmetic/IMUL.md) | Multiplicação com sinal (formas flexíveis) |
| [DIV](Arithmetic/DIV.md) | Divisão sem sinal + resto |
| [IDIV](Arithmetic/IDIV.md) | Divisão com sinal + resto |
| [NEG](Arithmetic/NEG.md) | Negação em complemento de dois |

### Lógica
| Instrução | Descrição |
|-----------|-----------|
| [AND](Logic/AND.md) | E lógico — mascarar / isolar bits |
| [OR](Logic/OR.md) | OU lógico — definir bits |
| [XOR](Logic/XOR.md) | XOR — alternar / zerar registrador |
| [NOT](Logic/NOT.md) | NOT lógico — complemento de um |
| [TEST](Logic/TEST.md) | AND sem modificar o destino |

### Comparação e Definição
| Instrução | Descrição |
|-----------|-----------|
| [CMP](Compare/CMP.md) | Comparar (SUB descartando resultado) |
| [SETcc](Compare/SETcc.md) | Definir byte como 0 ou 1 por condição |

### Saltos
| Instrução | Descrição |
|-----------|-----------|
| [JMP](Jump/JMP.md) | Salto incondicional |
| [JE / JZ](Jump/JE.md) | Saltar se igual / zero |
| [JNE / JNZ](Jump/JNE.md) | Saltar se diferente / não zero |
| [JL / JNGE](Jump/JL.md) | Saltar se menor (com sinal) |
| [JLE / JNG](Jump/JLE.md) | Saltar se menor ou igual (com sinal) |
| [JG / JNLE](Jump/JG.md) | Saltar se maior (com sinal) |
| [JGE / JNL](Jump/JGE.md) | Saltar se maior ou igual (com sinal) |
| [JC / JB](Jump/JC.md) | Saltar se carry / abaixo (sem sinal) |
| [JNC / JAE](Jump/JNC.md) | Saltar se sem carry / acima ou igual |
| [JO / JNO](Jump/JO.md) | Saltar se overflow |
| [LOOP](Jump/LOOP.md) | Decrementar RCX e saltar se não zero |

### Pilha e Chamadas
| Instrução | Descrição |
|-----------|-----------|
| [CALL](Stack/CALL.md) | Chamar sub-rotina (empilha endereço de retorno + salta) |
| [RET](Stack/RET.md) | Retornar de sub-rotina |
| [ENTER](Stack/ENTER.md) | Criar frame de pilha |
| [LEAVE](Stack/LEAVE.md) | Destruir frame de pilha |

### Deslocamentos e Rotações
| Instrução | Descrição |
|-----------|-----------|
| [SHL / SAL](Shift/SHL.md) | Deslocar à esquerda (×2ⁿ) |
| [SHR](Shift/SHR.md) | Deslocar à direita lógico (÷2ⁿ sem sinal) |
| [SAR](Shift/SAR.md) | Deslocar à direita aritmético (÷2ⁿ com sinal) |
| [ROL](Shift/ROL.md) | Rotacionar à esquerda |
| [ROR](Shift/ROR.md) | Rotacionar à direita |
| [RCL](Shift/RCL.md) | Rotacionar à esquerda pelo carry |
| [RCR](Shift/RCR.md) | Rotacionar à direita pelo carry |

### String / Memória em Massa
| Instrução | Descrição |
|-----------|-----------|
| [MOVSB/W/D](String/MOVSB.md) | Copiar memória (como `memcpy`) |
| [STOS](String/STOS.md) | Preencher memória (como `memset`) |
| [LODS](String/LODS.md) | Carregar byte/word/dword de string |
| [SCAS](String/SCAS.md) | Escanear memória (como `memchr` / `strlen`) |
| [CMPS](String/CMPS.md) | Comparar memória (como `memcmp`) |

### Controle de Flags
| Instrução | Descrição |
|-----------|-----------|
| [CLC](Flags/CLC.md) | Limpar Carry Flag |
| [STC](Flags/STC.md) | Definir Carry Flag |
| [CLD](Flags/CLD.md) | Limpar Direction Flag (operações para frente) |
| [STD](Flags/STD.md) | Definir Direction Flag (operações para trás) |
| [CLI](Flags/CLI.md) | Desabilitar interrupções de hardware (ring 0) |
| [STI](Flags/STI.md) | Habilitar interrupções de hardware (ring 0) |

### Miscelânea
| Instrução | Descrição |
|-----------|-----------|
| [NOP](Misc/NOP.md) | Nenhuma operação (alinhamento / patching) |
| [INT](Misc/INT.md) | Interrupção de software / breakpoint INT3 |
| [SYSCALL](Misc/SYSCALL.md) | Chamada de sistema rápida 64 bits |
| [CPUID](Misc/CPUID.md) | Detectar recursos da CPU em tempo de execução |
| [RDTSC](Misc/RDTSC.md) | Ler contador de timestamp (benchmarking) |
| [HLT](Misc/HLT.md) | Parar CPU (idle do kernel / desligamento) |

---

## 💡 Conceitos Fundamentais

### EFLAGS — O Registrador de Códigos de Condição

A maioria das instruções aritméticas e lógicas atualiza EFLAGS:

| Flag | Nome | Definida quando… |
|------|------|-----------------|
| **CF** | Carry (Transporte) | Overflow/borrow sem sinal |
| **OF** | Overflow | Overflow com sinal |
| **ZF** | Zero | Resultado = 0 |
| **SF** | Sign (Sinal) | Resultado é negativo (MSB = 1) |
| **PF** | Parity (Paridade) | Byte baixo tem número par de bits 1 |
| **DF** | Direction (Direção) | Controla direção de ops de string (CLD/STD) |

### Comparações Com Sinal vs Sem Sinal

```asm
; Após CMP, use a família de salto correta:

; Com sinal:  JL / JLE / JG / JGE
; Sem sinal:  JB / JBE / JA / JAE

CMP  eax, ebx
JL   menor_com_sinal      ; com sinal: eax < ebx
JB   abaixo_sem_sinal     ; sem sinal: eax < ebx
```

### ABI System V AMD64 — Convenção de Chamada (Linux / macOS)

```asm
; Argumentos inteiros: RDI, RSI, RDX, RCX, R8, R9
; Valor de retorno: RAX
; Caller-saved (temporários): RAX, RCX, RDX, RSI, RDI, R8–R11
; Callee-saved (preservar): RBX, RBP, R12–R15
; Pilha deve estar alinhada em 16 bytes antes de CALL
```

### Registradores de Uso Geral (x86-64)

```
64 bits  32 bits  16 bits  8 bits alto  8 bits baixo
RAX      EAX      AX       AH           AL
RBX      EBX      BX       BH           BL
RCX      ECX      CX       CH           CL
RDX      EDX      DX       DH           DL
RSI      ESI      SI       —            SIL
RDI      EDI      DI       —            DIL
RSP      ESP      SP       —            SPL   (ponteiro de pilha)
RBP      EBP      BP       —            BPL   (base pointer)
R8–R15   R8D–R15D R8W–R15W —            R8B–R15B
```

---

## 🔧 Ferramentas e Ambiente

| Ferramenta | Finalidade |
|------------|-----------|
| [NASM](https://nasm.us/) | Montador (sintaxe Intel) — recomendado |
| [GAS (GNU as)](https://www.gnu.org/software/binutils/) | Montador (sintaxe AT&T, também suporta Intel) |
| [GDB](https://www.gnu.org/software/gdb/) | Depurador — `layout asm` para visualização assembly |
| [radare2](https://rada.re/) | Engenharia reversa e desmontagem |
| [Godbolt](https://godbolt.org/) | Compiler Explorer — veja o ASM gerado online |
| [Intel XED](https://intelxed.github.io/) | Biblioteca de codificação/decodificação de instruções |

### Comandos Úteis do GDB

```bash
(gdb) layout asm         # exibir visão de desmontagem
(gdb) info registers     # dumpar todos os registradores
(gdb) x/10i $rip         # desmontar 10 instruções a partir de RIP
(gdb) x/4xg $rsp         # mostrar 4 qwords na pilha
(gdb) stepi              # executar uma instrução
(gdb) ni                 # próxima instrução (pular chamadas)
```

---

## 📚 Referências

- [Manuais do Desenvolvedor de Software Intel® 64 e IA-32](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [Manual do Programador de Arquitetura AMD64](https://developer.amd.com/resources/developer-guides-manuals/)
- [Referência x86 de Felix Cloutier](https://www.felixcloutier.com/x86/) — versão online pesquisável do Intel SDM
- [OSDev Wiki — Referência de Instruções x86](https://wiki.osdev.org/X86-64_Instruction_Encoding)
- [Agner Fog — Tabelas de Instruções](https://www.agner.org/optimize/) — latência e throughput para os principais CPUs

---

## 🤝 Contribuindo

Contribuições são bem-vindas! Fique à vontade para abrir issues ou pull requests para:

- Correções ou melhorias na documentação existente
- Instruções ausentes ou casos especiais
- Exemplos práticos adicionais
- Novas categorias de instruções (SSE, AVX, BMI, etc.)

---

## 📄 Licença

Este projeto está licenciado sob a [Licença MIT](../../LICENSE).

---

<div align="center">

Feito com ❤️ para a comunidade de programação de baixo nível

</div>

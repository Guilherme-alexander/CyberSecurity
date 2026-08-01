<div align="center">

# 🖥️ x86 Assembly — Instruction Reference

**A professional, example-driven reference for x86/x86-64 assembly instructions.**

[![Language](https://img.shields.io/badge/Language-x86%20Assembly-blue?style=flat-square&logo=assemblyscript)](https://en.wikipedia.org/wiki/X86_assembly_language)
[![Architecture](https://img.shields.io/badge/Architecture-x86%20%7C%20x86--64-orange?style=flat-square)](https://en.wikipedia.org/wiki/X86-64)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Docs](https://img.shields.io/badge/Docs-69%20instructions-purple?style=flat-square)](.)

[🇧🇷 Leia em Português](./README.pt-BR.md)

</div>

---

## 📖 About

This reference covers **69 x86/x86-64 instructions** organized into 10 categories. Each file follows a consistent structure:

- **Syntax** — exact assembler notation
- **Description** — what the instruction does and when to use it
- **Flags affected** — how EFLAGS is modified
- **Practical examples** — commented, real-world code patterns
- **Notes** — pitfalls, performance tips, and edge cases
- **See also** — cross-links to related instructions

All examples use **Intel syntax** (NASM/YASM compatible) and target **64-bit mode** unless noted otherwise.

---

## 📂 Directory Structure

```
docs/
├── DataTransfer/       # Moving data between registers and memory
│   ├── MOV.md          # Move — the most fundamental instruction
│   ├── LEA.md          # Load Effective Address — pointer arithmetic
│   ├── XCHG.md         # Exchange — atomic swap
│   ├── PUSH.md         # Push onto stack
│   ├── POP.md          # Pop from stack
│   ├── MOVSX.md        # Move with Sign-Extension (signed integers)
│   ├── MOVZX.md        # Move with Zero-Extension (unsigned integers)
│   └── CMOV.md         # Conditional Move — branchless selection
│
├── Arithmetic/         # Integer arithmetic operations
│   ├── ADD.md          # Add
│   ├── SUB.md          # Subtract
│   ├── INC.md          # Increment by 1
│   ├── DEC.md          # Decrement by 1
│   ├── MUL.md          # Unsigned multiply
│   ├── IMUL.md         # Signed multiply (flexible 2/3-operand forms)
│   ├── DIV.md          # Unsigned divide
│   ├── IDIV.md         # Signed divide
│   └── NEG.md          # Two's complement negation
│
├── Logic/              # Bitwise logical operations
│   ├── AND.md          # Bitwise AND — mask / clear bits
│   ├── OR.md           # Bitwise OR — set bits
│   ├── XOR.md          # Bitwise XOR — toggle / zero idiom
│   ├── NOT.md          # Bitwise NOT — one's complement
│   └── TEST.md         # Non-destructive AND — flag-only check
│
├── Compare/            # Comparison and conditional byte set
│   ├── CMP.md          # Compare — non-destructive subtract
│   ├── SETcc.md        # Set byte on condition (branchless bool)
│   └── TEST.md         # → See Logic/TEST.md
│
├── Jump/               # Control flow — branches and loops
│   ├── JMP.md          # Unconditional jump
│   ├── JE.md           # Jump if Equal (ZF=1)
│   ├── JNE.md          # Jump if Not Equal (ZF=0)
│   ├── JL.md           # Jump if Less — signed
│   ├── JLE.md          # Jump if Less or Equal — signed
│   ├── JG.md           # Jump if Greater — signed
│   ├── JGE.md          # Jump if Greater or Equal — signed
│   ├── JC.md           # Jump if Carry / Below — unsigned
│   ├── JNC.md          # Jump if No Carry / Above or Equal
│   ├── JO.md           # Jump if Overflow
│   └── LOOP.md         # Decrement counter and loop
│
├── Stack/              # Call stack management
│   ├── PUSH.md         # → See DataTransfer/PUSH.md
│   ├── POP.md          # → See DataTransfer/POP.md
│   ├── CALL.md         # Call subroutine — pushes return address
│   ├── RET.md          # Return from subroutine
│   ├── ENTER.md        # Create stack frame (prologue)
│   └── LEAVE.md        # Destroy stack frame (epilogue)
│
├── Shift/              # Bit shifting and rotation
│   ├── SHL.md          # Shift Left Logical (×2ⁿ)
│   ├── SHR.md          # Shift Right Logical (÷2ⁿ unsigned)
│   ├── SAR.md          # Shift Right Arithmetic (÷2ⁿ signed)
│   ├── SAL.md          # Shift Arithmetic Left (= SHL)
│   ├── ROL.md          # Rotate Left — bits wrap around
│   ├── ROR.md          # Rotate Right — bits wrap around
│   ├── RCL.md          # Rotate Left through Carry
│   └── RCR.md          # Rotate Right through Carry
│
├── String/             # Bulk memory / string operations
│   ├── MOVSB.md        # Move String Byte (memcpy)
│   ├── MOVSW.md        # Move String Word
│   ├── MOVSD.md        # Move String Doubleword
│   ├── STOS.md         # Store String (memset)
│   ├── LODS.md         # Load String — iterate bytes
│   ├── SCAS.md         # Scan String (memchr / strlen)
│   └── CMPS.md         # Compare Strings (memcmp)
│
├── Flags/              # Direct flag manipulation
│   ├── CLC.md          # Clear Carry Flag
│   ├── STC.md          # Set Carry Flag
│   ├── CLD.md          # Clear Direction Flag (forward string ops)
│   ├── STD.md          # Set Direction Flag (backward string ops)
│   ├── CLI.md          # Clear Interrupt Flag — disable IRQs (ring 0)
│   └── STI.md          # Set Interrupt Flag — enable IRQs (ring 0)
│
└── Misc/               # System and utility instructions
    ├── NOP.md          # No Operation — alignment, patching
    ├── INT.md          # Software Interrupt (INT3 breakpoint, syscalls)
    ├── SYSCALL.md      # Fast 64-bit system call (Linux/macOS)
    ├── CPUID.md        # CPU feature detection
    ├── RDTSC.md        # Read Time-Stamp Counter (benchmarking)
    └── HLT.md          # Halt processor (kernel idle loop)
```

---

## 🚀 Quick Start

### Hello World — Linux x86-64 (NASM)

```asm
section .data
    msg db "Hello, World!", 10
    len equ $ - msg

section .text
    global _start

_start:
    ; write(1, msg, len)
    mov rax, 1          ; syscall: sys_write
    mov rdi, 1          ; fd: stdout
    lea rsi, [msg]      ; buffer pointer
    mov rdx, len        ; byte count
    syscall

    ; exit(0)
    mov rax, 60         ; syscall: sys_exit
    xor rdi, rdi        ; exit code: 0
    syscall
```

```bash
nasm -f elf64 hello.asm -o hello.o
ld -o hello hello.o
./hello
```

---

## 📋 Instruction Index

### Data Transfer
| Instruction | Description |
|-------------|-------------|
| [MOV](DataTransfer/MOV.md) | Copy value between register/memory |
| [LEA](DataTransfer/LEA.md) | Load computed address (pointer math) |
| [XCHG](DataTransfer/XCHG.md) | Atomic swap of two operands |
| [PUSH](DataTransfer/PUSH.md) | Push value onto stack |
| [POP](DataTransfer/POP.md) | Pop value from stack |
| [MOVSX](DataTransfer/MOVSX.md) | Move with sign-extension (signed types) |
| [MOVZX](DataTransfer/MOVZX.md) | Move with zero-extension (unsigned types) |
| [CMOV](DataTransfer/CMOV.md) | Conditional move (branchless select) |

### Arithmetic
| Instruction | Description |
|-------------|-------------|
| [ADD](Arithmetic/ADD.md) | Integer addition |
| [SUB](Arithmetic/SUB.md) | Integer subtraction |
| [INC](Arithmetic/INC.md) | Increment by 1 (CF unaffected) |
| [DEC](Arithmetic/DEC.md) | Decrement by 1 (CF unaffected) |
| [MUL](Arithmetic/MUL.md) | Unsigned multiply (wide result) |
| [IMUL](Arithmetic/IMUL.md) | Signed multiply (flexible forms) |
| [DIV](Arithmetic/DIV.md) | Unsigned divide + remainder |
| [IDIV](Arithmetic/IDIV.md) | Signed divide + remainder |
| [NEG](Arithmetic/NEG.md) | Two's complement negate |

### Logic
| Instruction | Description |
|-------------|-------------|
| [AND](Logic/AND.md) | Bitwise AND — mask / isolate bits |
| [OR](Logic/OR.md) | Bitwise OR — set bits |
| [XOR](Logic/XOR.md) | Bitwise XOR — toggle / zero register |
| [NOT](Logic/NOT.md) | Bitwise NOT — one's complement |
| [TEST](Logic/TEST.md) | AND without modifying destination |

### Compare & Set
| Instruction | Description |
|-------------|-------------|
| [CMP](Compare/CMP.md) | Compare (SUB discarding result) |
| [SETcc](Compare/SETcc.md) | Set byte to 0 or 1 by condition |

### Jumps
| Instruction | Description |
|-------------|-------------|
| [JMP](Jump/JMP.md) | Unconditional jump |
| [JE / JZ](Jump/JE.md) | Jump if equal / zero |
| [JNE / JNZ](Jump/JNE.md) | Jump if not equal / not zero |
| [JL / JNGE](Jump/JL.md) | Jump if less (signed) |
| [JLE / JNG](Jump/JLE.md) | Jump if less or equal (signed) |
| [JG / JNLE](Jump/JG.md) | Jump if greater (signed) |
| [JGE / JNL](Jump/JGE.md) | Jump if greater or equal (signed) |
| [JC / JB](Jump/JC.md) | Jump if carry / below (unsigned) |
| [JNC / JAE](Jump/JNC.md) | Jump if no carry / above or equal |
| [JO / JNO](Jump/JO.md) | Jump if overflow |
| [LOOP](Jump/LOOP.md) | Decrement RCX and jump if non-zero |

### Stack & Calls
| Instruction | Description |
|-------------|-------------|
| [CALL](Stack/CALL.md) | Call subroutine (push return address + jump) |
| [RET](Stack/RET.md) | Return from subroutine |
| [ENTER](Stack/ENTER.md) | Create stack frame |
| [LEAVE](Stack/LEAVE.md) | Destroy stack frame |

### Shifts & Rotations
| Instruction | Description |
|-------------|-------------|
| [SHL / SAL](Shift/SHL.md) | Shift left (×2ⁿ) |
| [SHR](Shift/SHR.md) | Shift right logical (÷2ⁿ unsigned) |
| [SAR](Shift/SAR.md) | Shift right arithmetic (÷2ⁿ signed) |
| [ROL](Shift/ROL.md) | Rotate left |
| [ROR](Shift/ROR.md) | Rotate right |
| [RCL](Shift/RCL.md) | Rotate left through carry |
| [RCR](Shift/RCR.md) | Rotate right through carry |

### String / Bulk Memory
| Instruction | Description |
|-------------|-------------|
| [MOVSB/W/D](String/MOVSB.md) | Memory copy (like `memcpy`) |
| [STOS](String/STOS.md) | Memory fill (like `memset`) |
| [LODS](String/LODS.md) | Load byte/word/dword from string |
| [SCAS](String/SCAS.md) | Scan memory (like `memchr` / `strlen`) |
| [CMPS](String/CMPS.md) | Compare memory (like `memcmp`) |

### Flag Control
| Instruction | Description |
|-------------|-------------|
| [CLC](Flags/CLC.md) | Clear Carry Flag |
| [STC](Flags/STC.md) | Set Carry Flag |
| [CLD](Flags/CLD.md) | Clear Direction Flag (forward ops) |
| [STD](Flags/STD.md) | Set Direction Flag (backward ops) |
| [CLI](Flags/CLI.md) | Disable hardware interrupts (ring 0) |
| [STI](Flags/STI.md) | Enable hardware interrupts (ring 0) |

### Miscellaneous
| Instruction | Description |
|-------------|-------------|
| [NOP](Misc/NOP.md) | No operation (alignment / patching) |
| [INT](Misc/INT.md) | Software interrupt / INT3 breakpoint |
| [SYSCALL](Misc/SYSCALL.md) | Fast 64-bit system call |
| [CPUID](Misc/CPUID.md) | Detect CPU features at runtime |
| [RDTSC](Misc/RDTSC.md) | Read timestamp counter (benchmarking) |
| [HLT](Misc/HLT.md) | Halt CPU (kernel idle / shutdown) |

---

## 💡 Key Concepts

### EFLAGS — The Condition Code Register

Most arithmetic and logic instructions update EFLAGS:

| Flag | Name | Set when… |
|------|------|-----------|
| **CF** | Carry | Unsigned overflow / borrow |
| **OF** | Overflow | Signed overflow |
| **ZF** | Zero | Result = 0 |
| **SF** | Sign | Result is negative (MSB = 1) |
| **PF** | Parity | Low byte has even number of 1-bits |
| **DF** | Direction | Controls string op direction (CLD/STD) |

### Signed vs Unsigned Comparisons

```asm
; After CMP, use the right jump family:

; Signed:   JL / JLE / JG / JGE
; Unsigned: JB / JBE / JA / JAE

CMP  eax, ebx
JL   signed_less          ; signed: eax < ebx
JB   unsigned_below       ; unsigned: eax < ebx
```

### System V AMD64 ABI — Calling Convention (Linux / macOS)

```asm
; Integer arguments: RDI, RSI, RDX, RCX, R8, R9
; Return value: RAX
; Caller-saved (scratch): RAX, RCX, RDX, RSI, RDI, R8–R11
; Callee-saved (preserve): RBX, RBP, R12–R15
; Stack must be 16-byte aligned before CALL
```

### General-Purpose Registers (x86-64)

```
64-bit   32-bit   16-bit   8-bit high   8-bit low
RAX      EAX      AX       AH           AL
RBX      EBX      BX       BH           BL
RCX      ECX      CX       CH           CL
RDX      EDX      DX       DH           DL
RSI      ESI      SI       —            SIL
RDI      EDI      DI       —            DIL
RSP      ESP      SP       —            SPL   (stack pointer)
RBP      EBP      BP       —            BPL   (base pointer)
R8–R15   R8D–R15D R8W–R15W —            R8B–R15B
```

---

## 🔧 Tools & Environment

| Tool | Purpose |
|------|---------|
| [NASM](https://nasm.us/) | Assembler (Intel syntax) — recommended |
| [GAS (GNU as)](https://www.gnu.org/software/binutils/) | Assembler (AT&T syntax, also supports Intel) |
| [GDB](https://www.gnu.org/software/gdb/) | Debugger — `layout asm` for assembly view |
| [radare2](https://rada.re/) | Reverse engineering and disassembly |
| [Godbolt](https://godbolt.org/) | Compiler Explorer — see generated ASM online |
| [Intel XED](https://intelxed.github.io/) | Instruction encoder/decoder library |

### Useful GDB Commands

```bash
(gdb) layout asm         # show disassembly view
(gdb) info registers     # dump all registers
(gdb) x/10i $rip         # disassemble 10 instructions from RIP
(gdb) x/4xg $rsp         # show 4 qwords on stack
(gdb) stepi              # step one instruction
(gdb) ni                 # next instruction (step over calls)
```

---

## 📚 References

- [Intel® 64 and IA-32 Architectures Software Developer Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [AMD64 Architecture Programmer's Manual](https://developer.amd.com/resources/developer-guides-manuals/)
- [Felix Cloutier's x86 Reference](https://www.felixcloutier.com/x86/) — searchable online version of the Intel SDM
- [OSDev Wiki — x86 Instruction Reference](https://wiki.osdev.org/X86-64_Instruction_Encoding)
- [Agner Fog — Instruction Tables](https://www.agner.org/optimize/) — latency and throughput data for all major CPUs

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or pull requests for:

- Corrections or improvements to existing documentation
- Missing instructions or edge cases
- Additional practical examples
- New instruction categories (SSE, AVX, BMI, etc.)

---

## 📄 License

This project is licensed under the [MIT License](../../LICENSE).

---

<div align="center">

Made with ❤️ for the low-level programming community

</div>

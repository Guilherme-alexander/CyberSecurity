# MOV — Move Data

## Syntax

```asm
MOV destination, source
```

## Description

Copies the value of `source` into `destination`. The original value of `source` is preserved. Both operands must be the same size. You **cannot** move memory-to-memory directly.

## Operand Combinations

| Source      | Destination | Allowed |
|-------------|-------------|---------|
| Register    | Register    | ✅      |
| Immediate   | Register    | ✅      |
| Memory      | Register    | ✅      |
| Register    | Memory      | ✅      |
| Immediate   | Memory      | ✅      |
| Memory      | Memory      | ❌      |
| Segment Reg | Register    | ✅      |

## Flags Affected

None. MOV never modifies EFLAGS.

## Examples

```asm
; Register <- Immediate
MOV eax, 42               ; eax = 42
MOV rax, 0x1122334455     ; rax = 0x0000001122334455 (64-bit)

; Register <- Register
MOV ebx, eax              ; ebx = eax

; Memory <- Register (store onto stack)
MOV [rbp-4], eax

; Register <- Memory (load from stack)
MOV eax, [rbp-4]

; Moving a 32-bit immediate into 64-bit register zero-extends upper 32 bits
MOV eax, 1                ; rax = 0x0000000000000001

; Segment register copy
MOV ax, ds                ; copy DS segment register into AX
```

## Common Idioms

```asm
; Zero out a register — prefer XOR (smaller encoding, same effect)
XOR eax, eax              ; eax = 0  (also clears upper 32 bits of rax)

; Preserve / restore a register around a call
PUSH rax
CALL some_function
POP rax

; Set up System V AMD64 ABI arguments
MOV rdi, rax              ; arg1
MOV rsi, rbx              ; arg2
MOV rdx, rcx              ; arg3
CALL my_function
```

## Notes

- Writing to a **32-bit register** (e.g., `eax`) in 64-bit mode **implicitly zeros the upper 32 bits** of the 64-bit register (`rax`).
- Writing to an **8-bit or 16-bit** sub-register (e.g., `al`, `ax`) does **not** affect the upper bits.
- `MOV` to/from control registers (`CR0`–`CR4`) requires **privilege level 0** (kernel mode).
- For smaller-to-larger transfers, prefer `MOVZX` (zero-extend) or `MOVSX` (sign-extend).

## See Also

- [`MOVSX`](./MOVSX.md) — Move with sign-extension
- [`MOVZX`](./MOVZX.md) — Move with zero-extension
- [`CMOV`](./CMOV.md) — Conditional move
- [`LEA`](./LEA.md) — Load effective address
- [`XCHG`](./XCHG.md) — Exchange two values

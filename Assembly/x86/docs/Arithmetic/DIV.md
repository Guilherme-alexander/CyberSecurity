# DIV — Unsigned Divide

## Syntax

```asm
DIV divisor
```

## Description

Performs **unsigned** integer division. The dividend is always in the implicit accumulator pair; the result is split into quotient and remainder.

## Implicit Operands

| Divisor | Dividend    | Quotient | Remainder |
|---------|-------------|----------|-----------|
| 8-bit   | AX          | AL       | AH        |
| 16-bit  | DX:AX       | AX       | DX        |
| 32-bit  | EDX:EAX     | EAX      | EDX       |
| 64-bit  | RDX:RAX     | RAX      | RDX       |

## Flags Affected

CF, OF, SF, ZF, PF, AF — all **Undefined** after DIV.

## Exceptions

- **#DE (Divide Error / Division by Zero)**: Raised if divisor = 0 **or** if the quotient doesn't fit in the destination register (quotient overflow).

## Examples

```asm
; 32-bit divide: EDX:EAX / ECX
XOR  edx, edx             ; clear upper half of dividend (important!)
MOV  eax, 100             ; dividend = 100
MOV  ecx, 7
DIV  ecx                  ; EAX = 14 (quotient), EDX = 2 (remainder)

; 64-bit divide
XOR  rdx, rdx             ; clear RDX
MOV  rax, 1000000
MOV  rbx, 7
DIV  rbx                  ; RAX = 142857, RDX = 1

; 8-bit divide
MOV ax, 250               ; AX = dividend
MOV bl, 10
DIV bl                    ; AL = 25 (quotient), AH = 0 (remainder)

; Get both quotient and remainder
MOV  eax, 17
XOR  edx, edx
MOV  ecx, 5
DIV  ecx
; EAX = 3 (quotient: 17 / 5)
; EDX = 2 (remainder: 17 % 5)
```

## Critical: Clear EDX Before 32-bit Division

```asm
; WRONG: EDX may contain garbage, causing #DE or wrong result
MOV eax, 10
MOV ecx, 3
DIV ecx                   ; DANGER if EDX != 0

; CORRECT: Zero EDX first
MOV  eax, 10
XOR  edx, edx             ; EDX:EAX = 0:10 = 10
MOV  ecx, 3
DIV  ecx                  ; EAX = 3, EDX = 1
```

## Division by Power of 2 (Faster Alternative)

```asm
; Prefer SHR for unsigned division by powers of 2
SHR eax, 1                ; eax / 2
SHR eax, 2                ; eax / 4
SHR eax, 3                ; eax / 8
; Remainder = eax & (divisor-1) before shift
```

## Notes

- DIV is **slow** — typically 20–90 cycles depending on operand size and CPU.
- Always zero EDX/RDX before a 32/64-bit DIV to prevent quotient overflow.
- For division by constants, compilers generate multiply-shift sequences instead of DIV for performance.

## See Also

- [`IDIV`](./IDIV.md) — Signed divide
- [`MUL`](./MUL.md) — Unsigned multiply
- [`SHR`](../Shift/SHR.md) — Shift right (fast divide by power of 2)
- [`AND`](../Logic/AND.md) — Bitwise AND (fast modulo by power of 2)

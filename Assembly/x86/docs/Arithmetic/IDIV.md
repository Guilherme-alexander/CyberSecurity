# IDIV — Signed Divide

## Syntax

```asm
IDIV divisor
```

## Description

Performs **signed** (two's complement) integer division. The dividend must be sign-extended across the register pair before dividing.

## Implicit Operands

| Divisor | Dividend | Quotient | Remainder |
|---------|----------|----------|-----------|
| 8-bit   | AX       | AL       | AH        |
| 16-bit  | DX:AX    | AX       | DX        |
| 32-bit  | EDX:EAX  | EAX      | EDX       |
| 64-bit  | RDX:RAX  | RAX      | RDX       |

The remainder has the same sign as the **dividend**.

## Flags Affected

CF, OF, SF, ZF, PF, AF — all **Undefined**.

## Exceptions

- **#DE**: Division by zero, or quotient out of range for the destination register.

## Sign-Extending the Dividend

Before IDIV, you must sign-extend the dividend into the high register. Use:

| Operation | Effect |
|-----------|--------|
| `CBW`     | Sign-extend AL → AX |
| `CWD`     | Sign-extend AX → DX:AX |
| `CDQ`     | Sign-extend EAX → EDX:EAX |
| `CQO`     | Sign-extend RAX → RDX:RAX |

## Examples

```asm
; Signed 32-bit division
MOV eax, -17
CDQ                       ; sign-extend EAX into EDX:EAX
MOV ecx, 5
IDIV ecx                  ; EAX = -3 (quotient), EDX = -2 (remainder)

; Positive / negative
MOV eax, 17
CDQ
MOV ecx, -5
IDIV ecx                  ; EAX = -3 (quotient), EDX = 2 (remainder)

; 64-bit signed divide
MOV  rax, -1000
CQO                       ; sign-extend RAX -> RDX:RAX
MOV  rbx, 7
IDIV rbx                  ; RAX = -142 (quotient), RDX = -6 (remainder)

; 8-bit signed divide
MOV  al, -50
CBW                       ; sign-extend AL -> AX
MOV  bl, 5
IDIV bl                   ; AL = -10, AH = 0
```

## DIV vs IDIV

```asm
; Value: EAX = 0xFFFFFFFB = -5 (signed) = 4294967291 (unsigned)
; Divisor: 2

; Unsigned DIV:
XOR  edx, edx
DIV  dword [two]          ; EAX = 2147483645 (0x7FFFFFFD)

; Signed IDIV:
CDQ
IDIV dword [two]          ; EAX = -2 (EAX = 0xFFFFFFFE), EDX = -1
```

## Notes

- Always use `CDQ` (32-bit) or `CQO` (64-bit) before IDIV, not `XOR edx, edx` (which would treat the dividend as unsigned).
- IDIV is the **slowest** common integer instruction — 20–100 cycles. Compilers replace division by constants with multiply-shift-add sequences.
- The remainder takes the sign of the **dividend** (C99 / truncation-toward-zero semantics).

## See Also

- [`DIV`](./DIV.md) — Unsigned divide
- [`IMUL`](./IMUL.md) — Signed multiply
- [`CDQ`] / `CQO` — Sign-extend for IDIV
- [`NEG`](./NEG.md) — Negate

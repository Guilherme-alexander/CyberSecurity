# NEG — Two's Complement Negate

## Syntax

```asm
NEG destination
```

## Description

Replaces `destination` with its two's complement negation. Equivalent to `SUB destination` from zero: `destination = 0 - destination`.

## Flags Affected

| Flag | Effect |
|------|--------|
| CF   | Set to 0 if destination was 0, otherwise set to 1 |
| OF   | Set if signed overflow (negating INT_MIN) |
| ZF   | Set if result = 0 |
| SF   | Set to sign bit of result |
| PF   | Updated |
| AF   | Updated |

## Examples

```asm
; Negate a register
MOV eax, 5
NEG eax                   ; eax = -5 (0xFFFFFFFB)

MOV eax, -5
NEG eax                   ; eax = 5

; Negate memory
NEG dword [rbp-4]

; Absolute value (branchless alternative to CMOV)
MOV  edx, eax
SAR  edx, 31              ; edx = 0 if positive, 0xFFFFFFFF if negative
XOR  eax, edx             ; conditionally flip bits
SUB  eax, edx             ; conditionally add 1 (two's complement)
; eax = |original_eax|

; Detect negation of zero (CF stays 0)
NEG eax
JNC not_zero              ; CF=0 only when original was 0

; Two's complement overflow: NEG of INT_MIN
MOV eax, 0x80000000       ; -2,147,483,648 (INT_MIN)
NEG eax                   ; eax = 0x80000000 again (no positive representation)
; OF = 1 (overflow!)
```

## NEG to Change Sign Before MUL

```asm
; Compute absolute value before unsigned multiply
MOV  eax, [signed_val]
TEST eax, eax
JGE  .positive
NEG  eax                  ; make positive for MUL
.positive:
MUL  ecx
```

## Notes

- `NEG eax` is equivalent to `NOT eax` + `ADD eax, 1` (two's complement definition).
- Negating zero yields zero (CF cleared, ZF set).
- Negating `INT_MIN` (0x80000000 for 32-bit) overflows and returns itself — OF is set to warn you.
- CF is set for all non-zero inputs, which is useful for multi-precision negation with SBB.

## Multi-Precision Negation (128-bit)

```asm
; Negate RDX:RAX
NEG  rax
ADC  rdx, 0               ; add carry to high word
NEG  rdx
```

## See Also

- [`NOT`](../Logic/NOT.md) — Bitwise NOT (one's complement)
- [`SUB`](./SUB.md) — Subtract (NEG = 0 - operand)
- [`IMUL`](./IMUL.md) — Signed multiply

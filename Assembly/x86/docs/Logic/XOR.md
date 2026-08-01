# XOR — Bitwise Exclusive OR

## Syntax

```asm
XOR destination, source
```

## Description

Performs a bitwise XOR (exclusive OR). Each result bit is 1 if the corresponding bits of the operands **differ**, and 0 if they are the same.

## Truth Table

| A | B | A XOR B |
|---|---|---------|
| 0 | 0 | 0       |
| 0 | 1 | 1       |
| 1 | 0 | 1       |
| 1 | 1 | 0       |

## Flags Affected

| Flag | Effect |
|------|--------|
| CF   | Cleared to 0 |
| OF   | Cleared to 0 |
| ZF   | Set if result = 0 |
| SF   | Set to sign bit of result |
| PF   | Updated |
| AF   | Undefined |

## Examples

```asm
; Zero a register (preferred idiom — smaller encoding than MOV eax, 0)
XOR eax, eax              ; eax = 0, ZF=1, CF=0, OF=0

; Toggle bits
XOR eax, 0xFF             ; flip low 8 bits
XOR eax, (1 << 3)         ; toggle bit 3

; Swap two registers without a temp (classic trick)
XOR eax, ebx              ; eax = eax ^ ebx
XOR ebx, eax              ; ebx = original eax
XOR eax, ebx              ; eax = original ebx
; (Prefer XCHG or PUSH/POP in practice — this confuses CPUs' register renaming)

; Check if two values are equal
XOR eax, ebx              ; if eax == ebx, result is 0
JZ  they_are_equal        ; ZF=1 iff eax == ebx

; Simple encryption / decryption (same key XOR twice = original)
XOR al, KEY               ; encrypt byte
XOR al, KEY               ; decrypt back to original

; Detect sign change
XOR eax, ebx              ; if MSBs differ, result MSB = 1
JS  signs_differ          ; SF=1 means opposite signs
```

## XOR eax, eax — The Canonical Zero Idiom

```asm
; These are all equivalent, but XOR eax, eax is preferred:
MOV  eax, 0               ; 5 bytes (in 32-bit), doesn't clear upper rax bits
XOR  eax, eax             ; 2 bytes, also zeros upper 32 bits of rax in 64-bit mode
SUB  eax, eax             ; 2 bytes, same but sets CF/OF differently
```

## Notes

- XOR with itself always yields 0 — the canonical register-zeroing idiom used by compilers.
- XOR is its own inverse: `(a XOR key) XOR key == a` — basis for simple stream ciphers.
- XOR always clears CF and OF.

## See Also

- [`AND`](./AND.md) — Bitwise AND
- [`OR`](./OR.md) — Bitwise OR
- [`NOT`](./NOT.md) — Bitwise NOT (XOR with all-ones)
- [`MOV`](../DataTransfer/MOV.md) — Move (alternative zero idiom)

# SAR — Shift Arithmetic Right (Signed)

## Syntax

```asm
SAR destination, count
```

## Description

Shifts all bits right by `count` positions, filling vacated left bits with a copy of the **sign bit** (MSB). This preserves the sign for signed integers. Equivalent to **signed integer division by 2ᴺ** (rounds toward negative infinity).

## Flags Affected

CF = last bit shifted out. OF = 0 when count=1. ZF/SF/PF updated.

## Examples

```asm
; Signed divide by powers of 2
MOV eax, -8
SAR eax, 1                ; eax = -4  (-8 / 2)
SAR eax, 1                ; eax = -2  (-4 / 2)
SAR eax, 1                ; eax = -1  (-2 / 2)
SAR eax, 1                ; eax = -1  (-1 / 2, rounds toward -inf)

; Propagate sign bit (fill register with sign)
SAR eax, 31               ; eax = 0 if positive, 0xFFFFFFFF if negative

; Branchless absolute value using SAR
MOV  edx, eax
SAR  edx, 31              ; edx = sign mask (0 or 0xFFFFFFFF)
XOR  eax, edx             ; conditionally invert
SUB  eax, edx             ; add 1 if negative (two's complement)

; Extract signed field from bitfield
MOV  eax, [packed_data]
SHL  eax, 24              ; shift field to top
SAR  eax, 24              ; sign-extend back down to 8-bit value
```

## SAR vs SHR

```asm
; eax = 0xFFFFFFFF = -1 signed = 4294967295 unsigned

SAR eax, 1                ; fills with 1: eax = 0xFFFFFFFF = -1 (signed)
                          ; -1 / 2 = 0 in C (truncates toward 0)
                          ; but SAR gives -1 (rounds toward -inf)

MOV eax, 0xFFFFFFFF
SHR eax, 1                ; fills with 0: eax = 0x7FFFFFFF = +2147483647 (unsigned)
```

> **Rounding difference from C:** C integer division truncates toward zero. SAR rounds toward negative infinity. For `-1 >> 1`, C gives 0, SAR gives -1.

## Notes

- Use SAR for **signed** values; `SHR` for **unsigned**.
- `SAR eax, 31` is the fastest way to create an all-0 or all-1 mask from the sign of `eax`.
- Maximum shift count is clamped to 63 (for 64-bit) or 31 (for 32-bit).

## See Also

- [`SHR`](./SHR.md) — Logical right shift (unsigned)
- [`SHL`](./SHL.md) / [`SAL`](./SAL.md) — Left shift
- [`NEG`](../Arithmetic/NEG.md) — Negate signed value

# RCR — Rotate Right Through Carry

## Syntax

```asm
RCR destination, count
```

## Description

Rotates the **concatenation** of `destination` and CF right by `count` bits. CF enters from the left (MSB side), the old LSB exits to CF.

## Operation (32-bit, count=1)

```
New CF    = old bit 0
New bit31 = old CF
Bits 30..0 = old bits 31..1 (shifted right)
```

## Examples

```asm
; Multi-precision right shift (128-bit in RDX:RAX)
SHR  rdx, 1               ; shift high qword; bit 0 of rdx -> CF
RCR  rax, 1               ; shift low qword; CF fills from left

; Read and clear LSB
RCR  eax, 1               ; old LSB -> CF, eax rotated
JC   lsb_was_one

; Signed multi-precision right shift
SAR  rdx, 1               ; arithmetic shift high qword (sign-preserving); bit0 -> CF
RCR  rax, 1               ; shift low qword with carry from high
```

## Multi-Precision Right Shift (Key Use Case)

```asm
; Unsigned right shift of 128-bit value in RDX:RAX by 1
SHR  rdx, 1               ; logical shift high; bit 0 goes to CF
RCR  rax, 1               ; CF enters bit 63 of rax; logical right shift

; Signed right shift of 128-bit value
SAR  rdx, 1               ; arithmetic shift high (sign bit duplicates); bit 0 -> CF
RCR  rax, 1               ; bring CF into rax from the left
```

## Notes

- RCR's primary use is **multi-precision arithmetic** for right shifts wider than 64 bits.
- For single-word rotations not needing CF, use ROR.

## See Also

- [`RCL`](./RCL.md) — Rotate left through carry
- [`ROR`](./ROR.md) — Rotate right (without CF involvement)
- [`SHR`](./SHR.md) / [`SAR`](./SAR.md) — Shift right

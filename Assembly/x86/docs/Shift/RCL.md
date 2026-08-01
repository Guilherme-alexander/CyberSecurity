# RCL — Rotate Left Through Carry

## Syntax

```asm
RCL destination, count
```

## Description

Rotates the **concatenation** of CF and `destination` left by `count` bits. CF enters from the right (LSB), the old MSB exits to CF. Think of it as a (N+1)-bit rotation where CF is the extra bit.

## Operation (32-bit, count=1)

```
New CF   = old bit 31
New bit0 = old CF
Bits 31..1 = old bits 30..0 (shifted left)
```

## Examples

```asm
; RCL by 1: shift in CF on the right, old MSB goes to CF
CLC                       ; CF = 0
MOV  eax, 0x80000001      ; 1000...0001
RCL  eax, 1               ; CF was 0 -> bit 0; old bit31(=1) -> CF
; eax = 0x00000002, CF = 1

; Multi-precision shift left (128-bit in RDX:RAX)
SHL  rax, 1               ; shift low qword; MSB -> CF
RCL  rdx, 1               ; shift high qword, bringing in CF from low part

; Read and clear MSB
RCL  eax, 1               ; old MSB -> CF, eax rotated
JC   msb_was_set

; Shift in a specific bit (from CF)
STC                       ; CF = 1
RCL  eax, 1               ; shift 1 in from right
```

## Multi-Precision Left Shift (Key Use Case)

```asm
; Shift a 128-bit number (rdx:rax) left by 1
SHL  rax, 1               ; shift lower 64 bits; bit 63 of rax -> CF
RCL  rdx, 1               ; shift upper 64 bits; CF from rax goes to bit 0 of rdx
```

## Notes

- RCL is primarily used for **multi-precision shifts** where the carry bridges between adjacent words.
- For single-word rotations that don't need CF involvement, use ROL.
- RCL by 1 is slower than ROL by 1 on most modern CPUs.

## See Also

- [`RCR`](./RCR.md) — Rotate right through carry
- [`ROL`](./ROL.md) — Rotate left (without CF involvement)
- [`SHL`](./SHL.md) — Shift left

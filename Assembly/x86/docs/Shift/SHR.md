# SHR — Shift Right Logical

## Syntax

```asm
SHR destination, count
```

## Description

Shifts all bits right by `count` positions, filling vacated left bits with **0**. The last shifted-out bit goes to CF. Equivalent to **unsigned integer division by 2ᴺ** (truncated).

## Flags Affected

CF = last bit shifted out. OF = former MSB (count=1). ZF/SF/PF updated.

## Examples

```asm
; Unsigned divide by powers of 2
SHR eax, 1                ; eax /= 2  (unsigned)
SHR eax, 2                ; eax /= 4
SHR eax, 3                ; eax /= 8

; Extract high byte of 16-bit value
SHR ax, 8                 ; ax = high byte (shifted to low position)

; Unsigned right-shift with remainder
MOV eax, 17
SHR eax, 2                ; eax = 4 (17 / 4 = 4, remainder 1)
; Remainder = original & 3 (before shift)

; Variable count
MOV cl, 4
SHR eax, cl               ; eax >>= 4

; Test the shifted-out bit
SHR eax, 1
JC  lsb_was_one           ; CF = original bit 0

; Parse nibbles from byte
MOVZX eax, byte [ptr]
MOV   ecx, eax
SHR   ecx, 4              ; ecx = high nibble (bits 7-4)
AND   eax, 0x0F           ; eax = low nibble (bits 3-0)
```

## SHR vs SAR

```asm
; Value: eax = 0xFFFFFFFF = -1 signed

SHR eax, 1                ; eax = 0x7FFFFFFF = 2147483647 (fills with 0)
; Result: positive — treats as unsigned

MOV eax, 0xFFFFFFFF
SAR eax, 1                ; eax = 0xFFFFFFFF = -1 (fills with sign bit 1)
; Result: -1 / 2 = 0 truncated? No: SAR gives -1 for -1>>1 (rounds toward -inf)
```

## Notes

- For **signed** right shifts, use `SAR` (preserves sign).
- Maximum count is masked to 5 bits (6 bits for 64-bit operands).
- `SHR eax, 1` is faster than `DIV 2` by a large margin.

## See Also

- [`SAR`](./SAR.md) — Signed (arithmetic) right shift
- [`SHL`](./SHL.md) — Left shift
- [`ROR`](./ROR.md) — Rotate right (bits wrap around)

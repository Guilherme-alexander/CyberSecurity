# ROR — Rotate Right

## Syntax

```asm
ROR destination, count
```

## Description

Rotates all bits right by `count` positions. Bits that shift off the **right** (LSB side) wrap around and re-enter from the **left** (MSB side).

## Flags Affected

CF = copy of the bit last rotated from LSB to MSB. OF = XOR of top two bits (count=1 only).

## Examples

```asm
; Rotate right by 1
MOV  eax, 0x00000001      ; 00000000 00000000 00000000 00000001
ROR  eax, 1               ; eax = 0x80000000, CF=1 (bit 0 moved to bit 31)

; Swap high and low 16 bits (rotate by 16)
ROR  eax, 16              ; eax: ABCD -> CDAB

; Variable count
MOV  cl, 8
ROR  eax, cl              ; rotate right by 8

; Endian swap of 32-bit value
MOV  eax, 0x12345678
ROR  eax, 8               ; 0x78123456
ROR  eax, 8               ; 0x56781234
ROR  eax, 8               ; 0x34567812
ROR  eax, 8               ; 0x12345678 (back to original after 4x)
; Better: use BSWAP for endian swap

; Read LSB then rotate
ROR  eax, 1
JC   lsb_was_one          ; CF = original bit 0
```

## ROR for Endian Swap

```asm
; Byte-reverse a 32-bit register (big-endian <-> little-endian)
; Prefer BSWAP instruction; ROR as fallback:
ROR  eax, 8               ; ABCD -> DABC
BSWAP eax                 ; ABCD -> DCBA (one instruction, same result)
```

## Notes

- Like ROL, bits are never lost — they rotate through.
- Common in cryptography: SHA-2 uses ROR with constants 2, 13, 22 (SHA-256).
- Count masked to 5 bits (32-bit) or 6 bits (64-bit).

## See Also

- [`ROL`](./ROL.md) — Rotate left
- [`RCR`](./RCR.md) — Rotate right through carry
- [`SHR`](./SHR.md) — Shift right (bits lost)
- `BSWAP` — Byte-swap for endian conversion

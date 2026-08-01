# SHL / SAL — Shift Left Logical / Shift Left Arithmetic

## Syntax

```asm
SHL destination, count
SAL destination, count
```

`count` is either an immediate (0–63) or `CL` register.

## Description

Shifts all bits left by `count` positions. The vacated right bits are filled with **0**. The leftmost shifted-out bit goes into CF. `SHL` and `SAL` are identical opcodes.

Shifting left by N is equivalent to **multiplying by 2ᴺ** (for unsigned values that don't overflow).

## Flags Affected

| Flag | Effect |
|------|--------|
| CF   | Last bit shifted out (bit 7/15/31/63) |
| OF   | Set if sign bit changed (count=1 only) |
| ZF   | Set if result = 0 |
| SF   | Set to sign bit of result |
| PF   | Updated |
| AF   | Undefined (count > 0) |

## Examples

```asm
; Multiply by powers of 2
SHL eax, 1                ; eax *= 2
SHL eax, 2                ; eax *= 4
SHL eax, 3                ; eax *= 8
SHL rax, 4                ; rax *= 16

; Variable shift count in CL
MOV cl, 5
SHL eax, cl               ; eax <<= 5 (multiply by 32)

; Build a bitmask for bit N
MOV eax, 1
SHL eax, cl               ; eax = 1 << N (bit N set)

; Shift and combine bytes into a 32-bit integer
MOVZX eax, byte [ptr]     ; byte 0 (high)
SHL   eax, 8
OR    al,  [ptr+1]        ; byte 1
SHL   eax, 8
OR    al,  [ptr+2]        ; byte 2
SHL   eax, 8
OR    al,  [ptr+3]        ; byte 3

; Detect overflow (bit shifted out)
SHL eax, 1
JC  overflow              ; CF=1: a '1' bit was shifted out
```

## Notes

- For **signed** left shifts that need arithmetic correctness, SAL is identical to SHL.
- For **right** shifts, the direction matters: `SHR` (logical, fills zeros) vs `SAR` (arithmetic, preserves sign).
- Shifting by 0 doesn't change CF (count=0 is a no-op).
- Maximum shift count is 63 for 64-bit operands (count is masked to 5 or 6 bits).

## See Also

- [`SHR`](./SHR.md) — Shift right logical (unsigned divide by 2ᴺ)
- [`SAR`](./SAR.md) — Shift right arithmetic (signed divide by 2ᴺ)
- [`ROL`](./ROL.md) — Rotate left (bits wrap around)
- [`IMUL`](../Arithmetic/IMUL.md) — Signed multiply by arbitrary constants

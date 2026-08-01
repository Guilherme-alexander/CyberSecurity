# OR — Bitwise OR

## Syntax

```asm
OR destination, source
```

## Description

Performs a bitwise OR, storing the result in `destination`. Each result bit is 1 if **either or both** corresponding operand bits are 1.

## Truth Table

| A | B | A OR B |
|---|---|--------|
| 0 | 0 | 0      |
| 0 | 1 | 1      |
| 1 | 0 | 1      |
| 1 | 1 | 1      |

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
; Set a specific bit
OR eax, 0x01              ; set bit 0 (make odd)
OR eax, (1 << 5)          ; set bit 5
OR eax, 0x80000000        ; set sign bit

; Combine flags/bitmask fields
MOV eax, READ_FLAG        ; 0x01
OR  eax, WRITE_FLAG       ; eax |= 0x02  => eax = 0x03

; OR with self to test for zero (non-destructive check)
OR  eax, eax              ; sets ZF if eax == 0, clears CF and OF
JZ  is_zero               ; (TEST eax, eax is preferred and equivalent)

; Build a bitmask for open() flags in Linux
MOV eax, 0                ; start clean
OR  eax, 0x0002           ; O_RDWR
OR  eax, 0x0200           ; O_CREAT
OR  eax, 0x0400           ; O_TRUNC

; Convert ASCII lowercase to uppercase (clear bit 5)
; 'a' = 0x61, 'A' = 0x41 — difference is bit 5
AND al, 0xDF              ; clear bit 5 (uppercase)

; Convert ASCII uppercase to lowercase (set bit 5)
OR  al, 0x20              ; set bit 5 (lowercase)
```

## Notes

- `OR eax, eax` is a common idiom to set flags based on eax without changing it (but `TEST eax, eax` is semantically clearer).
- OR always clears CF and OF.
- Cannot take two memory operands.

## See Also

- [`AND`](./AND.md) — Bitwise AND (clear bits)
- [`XOR`](./XOR.md) — Bitwise XOR (toggle bits)
- [`NOT`](./NOT.md) — Bitwise NOT
- [`TEST`](./TEST.md) — Non-destructive AND for flag-testing

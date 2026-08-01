# AND — Bitwise AND

## Syntax

```asm
AND destination, source
```

## Description

Performs a bitwise AND between `destination` and `source`, storing the result in `destination`. Each bit of the result is 1 only if the corresponding bits of **both** operands are 1.

## Truth Table

| A | B | A AND B |
|---|---|---------|
| 0 | 0 | 0       |
| 0 | 1 | 0       |
| 1 | 0 | 0       |
| 1 | 1 | 1       |

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
; Bit masking — isolate the low byte
AND eax, 0xFF             ; eax &= 0xFF (clear upper 24 bits)

; Check if bit N is set (use TEST instead when you don't need result)
AND eax, 0x01             ; isolate bit 0 (check odd/even)
JZ  is_even

; Clear specific bits
AND eax, 0xFFFFFFF0       ; clear lower 4 bits
AND eax, ~(1 << 3)        ; clear bit 3 (in assembler supporting ~ operator)

; Align address down to 16-byte boundary
AND rsp, ~0xF             ; rsp &= 0xFFFFFFFFFFFFFFF0

; Mask higher bits
AND eax, 0x0000FFFF       ; keep only lower 16 bits (zero-extend effect)

; Fast modulo by power of 2 (for unsigned values)
AND eax, 63               ; eax = eax % 64  (same as eax & (64-1))
AND eax, 7                ; eax = eax % 8
```

## Bit Testing (Use TEST for flags only)

```asm
; TEST is AND that discards the result — preferred for flag-checking
TEST eax, 0x80            ; check bit 7 without modifying eax
JNZ  bit7_is_set

; AND modifies the destination (if you also need the masked value):
AND eax, 0x0F             ; eax = lower nibble, ZF set if it was 0
```

## Common Mask Values

| Mask       | Purpose                        |
|------------|--------------------------------|
| `0xFF`     | Keep low byte (bits 0–7)       |
| `0xFFFF`   | Keep low word (bits 0–15)      |
| `0xFFFFFFF0` | Clear low nibble             |
| `~0xF`     | 16-byte align (clear low 4 bits)|
| `1 << N`   | Isolate bit N                  |

## Notes

- AND always clears CF and OF — useful to explicitly clear these flags.
- After AND, if result == 0, ZF=1.
- For checking flags without modification, prefer `TEST`.

## See Also

- [`OR`](./OR.md) — Bitwise OR (set bits)
- [`XOR`](./XOR.md) — Bitwise XOR (toggle bits)
- [`NOT`](./NOT.md) — Bitwise NOT (invert all bits)
- [`TEST`](./TEST.md) — AND that only sets flags (non-destructive)

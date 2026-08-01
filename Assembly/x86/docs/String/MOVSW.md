# MOVSW — Move String Word (2 bytes)

## Syntax

```asm
MOVSW
REP MOVSW
```

## Description

Copies a **2-byte word** from `[RSI]` to `[RDI]` and adjusts both pointers by 2. Same as MOVSB but operates on 16-bit (word) units.

## Examples

```asm
; Copy 10 words (20 bytes) forward
CLD
LEA  rsi, [src]
LEA  rdi, [dst]
MOV  rcx, 10
REP  MOVSW               ; copies 20 bytes, 2 at a time

; Mix MOVSQ + MOVSW + MOVSB for arbitrary lengths
MOV  rcx, LENGTH / 8
REP  MOVSQ
MOV  rcx, (LENGTH % 8) / 2
REP  MOVSW
MOV  rcx, LENGTH % 2
REP  MOVSB
```

## Notes

- MOVSW advances RSI/RDI by 2 per iteration.
- Prefer MOVSQ (8 bytes) for bulk copies; MOVSW for 16-bit data structures or residual bytes.

## See Also

- [`MOVSB`](./MOVSB.md) — Move byte
- [`MOVSD`](./MOVSD.md) — Move doubleword (4 bytes)

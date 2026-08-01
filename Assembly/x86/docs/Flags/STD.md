# STD — Set Direction Flag

## Syntax

```asm
STD
```

## Description

Sets the Direction Flag (DF) to 1. When DF=1, string instructions **decrement** RSI/RDI after each operation (backward direction). Used for overlapping memory copies where destination is above source.

## Flags Affected

**DF = 1**. No other flags modified.

## Examples

```asm
; Backward copy: safe when dst > src and ranges overlap
STD
LEA  rsi, [src + LENGTH - 1]   ; point to last source byte
LEA  rdi, [dst + LENGTH - 1]   ; point to last dest byte
MOV  rcx, LENGTH
REP  MOVSB                ; copies backward
CLD                       ; ALWAYS restore DF after backward copy

; Overlapping memmove where dst > src (forward copy would corrupt)
; Example: memmove(buf+1, buf, 10) — shift array right by 1
LEA  rsi, [buf + 9]       ; last source byte
LEA  rdi, [buf + 10]      ; last dest byte
MOV  rcx, 10
STD
REP  MOVSB
CLD
```

## Warning

```asm
; ALWAYS restore DF to 0 after using STD
STD
REP  MOVSB
CLD               ; ← do not omit! ABI requires DF=0 at function boundaries
```

## Notes

- STD should be used only when necessary (overlapping buffers, dst > src) and always paired with CLD afterward.
- Many bugs arise from calling a function while DF=1 — string operations inside the callee will run backward.

## See Also

- [`CLD`](./CLD.md) — Clear Direction Flag (normal forward mode)
- [`MOVSB`](../String/MOVSB.md) — Move string byte

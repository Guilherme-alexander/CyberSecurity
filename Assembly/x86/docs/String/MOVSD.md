# MOVSD — Move String Doubleword (4 bytes)

## Syntax

```asm
MOVSD
REP MOVSD
```

## Description

Copies a **4-byte doubleword** from `[RSI]` to `[RDI]`, adjusting both pointers by 4.

> **Note:** In NASM/YASM with SSE extensions, `MOVSD` is also an SSE2 instruction (Move Scalar Double). Context (operands) determines which form is assembled.

## Examples

```asm
; Copy array of 32-bit integers
CLD
LEA  rsi, [int_array_src]
LEA  rdi, [int_array_dst]
MOV  rcx, ARRAY_LEN       ; number of elements (not bytes)
REP  MOVSD                ; copies ARRAY_LEN * 4 bytes

; Copy 32-bit integer struct fields
; (equivalent to memcpy for 4-byte aligned structs)
```

## Notes

- Adjusts pointers by 4 per iteration.
- MOVSD in 64-bit mode can be confused with SSE2 MOVSD (scalar double); in string context, it takes no operands.

## See Also

- [`MOVSB`](./MOVSB.md) — Move byte
- [`MOVSW`](./MOVSW.md) — Move word

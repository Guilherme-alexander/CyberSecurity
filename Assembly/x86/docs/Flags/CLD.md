# CLD — Clear Direction Flag

## Syntax

```asm
CLD
```

## Description

Clears the Direction Flag (DF) to 0. When DF=0, string instructions (MOVSB, STOSB, SCASB, etc.) **increment** RSI/RDI after each operation (forward direction).

## Flags Affected

**DF = 0**. No other flags are modified.

## Examples

```asm
; Always CLD before REP string operations in normal code
CLD
LEA  rsi, [src]
LEA  rdi, [dst]
MOV  rcx, LENGTH
REP  MOVSB                ; copies forward: src[0..N] -> dst[0..N]

; Restore DF after backward copy
STD                       ; DF=1 for backward copy
; ... backward copy ...
CLD                       ; restore DF to 0 (good practice)
```

## Notes

- The **System V AMD64 ABI** (Linux) requires DF=0 at function call boundaries. Always CLD before string ops and before calling external functions.
- DF is preserved across system calls.
- Forgetting CLD is a common bug — string ops silently process memory backward.

## See Also

- [`STD`](./STD.md) — Set Direction Flag (backward string ops)
- [`MOVSB`](../String/MOVSB.md), [`STOSB`](../String/STOS.md), [`SCASB`](../String/SCAS.md)

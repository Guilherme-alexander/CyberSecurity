# JG — Jump if Greater (Signed)

## Syntax

```asm
JG label
```

Alias: `JNLE` (Jump if Not Less or Equal)

## Description

Jumps if the signed comparison is "greater than" — ZF=0 AND SF=OF.

## Examples

```asm
CMP  eax, ebx
JG   greater              ; jump if eax > ebx (signed)

; Skip if not greater than threshold
CMP  eax, THRESHOLD
JG   over_threshold

; Find maximum of two signed values
CMP  eax, ebx
JG   .eax_wins
MOV  eax, ebx             ; ebx is greater or equal
.eax_wins:                ; eax holds max
```

## See Also

- [`JGE`](./JGE.md) — Jump if Greater or Equal
- [`JL`](./JL.md) — Opposite condition
- [`JA`](./JC.md) — Unsigned equivalent (above)

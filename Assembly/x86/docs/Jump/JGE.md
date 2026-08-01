# JGE — Jump if Greater or Equal (Signed)

## Syntax

```asm
JGE label
```

Alias: `JNL` (Jump if Not Less)

## Description

Jumps if signed comparison is "greater than or equal" — SF=OF.

## Examples

```asm
CMP  eax, 0
JGE  non_negative         ; jump if eax >= 0 (signed)

CMP  eax, MIN
JGE  above_min            ; skip if eax < MIN

; Do-while: run at least once, continue while >= threshold
.do:
    ; ... body ...
    DEC  eax
    CMP  eax, THRESHOLD
    JGE  .do
```

## See Also

- [`JG`](./JG.md) — Strict greater than
- [`JL`](./JL.md) — Opposite
- [`JAE`](./JC.md) — Unsigned equivalent (above or equal / no carry)

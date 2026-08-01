# JLE — Jump if Less or Equal (Signed)

## Syntax

```asm
JLE label
```

Alias: `JNG` (Jump if Not Greater)

## Description

Jumps if the signed comparison is "less than **or** equal" — ZF=1 OR SF≠OF.

## Examples

```asm
CMP  eax, ebx
JLE  at_most              ; jump if eax <= ebx (signed)

; Loop up to and including N
CMP  ecx, N
JLE  .loop_body

; For loop: i <= last_index
MOV  ecx, 0
.for:
    CMP  ecx, last_index
    JG   .done            ; exit when i > last_index
    ; ... body ...
    INC  ecx
    JMP  .for
.done:
```

## See Also

- [`JL`](./JL.md) — Jump if Less (strict)
- [`JGE`](./JGE.md) — Opposite condition
- [`JBE`](./JC.md) — Unsigned equivalent

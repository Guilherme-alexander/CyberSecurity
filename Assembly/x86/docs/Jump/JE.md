# JE — Jump if Equal / Zero

## Syntax

```asm
JE label
```

## Description

Jumps to `label` if the condition **Equal / Zero** is true (ZF=1). Usually follows a `CMP` or `TEST` instruction.

## Condition

| Mnemonic | Aliases | Condition | Flags |
|----------|---------|-----------|-------|
| JE | JZ | Equal / Zero | ZF=1 |

## Flags Read

ZF

## Examples

```asm
; After CMP
CMP  eax, ebx
JE  they_are_equal

; After SUB (ZF set if result = 0)
SUB  eax, 5
JE  result_was_zero     ; JE fires if eax was 5

; After TEST (check for zero / null)
TEST rdi, rdi
JE  null_ptr              ; jump if rdi == 0

; While loop pattern
.while:
    CMP  ecx, 10
    JE  .end_while
    ; ... body ...
    INC  ecx
    JMP  .while
.end_while:
```

## Notes

- JE is functionally identical to its alias (JZ) — same opcode, different mnemonic for readability.
- The jump range is ±2 GB in 64-bit mode (near jump).

## See Also

- [`CMP`](../Compare/CMP.md) — Compare (primary flag setter)
- [`TEST`](../Logic/TEST.md) — Non-destructive AND
- [`JMP`](./JMP.md) — Unconditional jump

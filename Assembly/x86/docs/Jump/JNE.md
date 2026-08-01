# JNE — Jump if Not Equal / Not Zero

## Syntax

```asm
JNE label
```

## Description

Jumps to `label` if the condition **Not Equal / Not Zero** is true (ZF=0). Usually follows a `CMP` or `TEST` instruction.

## Condition

| Mnemonic | Aliases | Condition | Flags |
|----------|---------|-----------|-------|
| JNE | JNZ | Not Equal / Not Zero | ZF=0 |

## Flags Read

ZF

## Examples

```asm
; After CMP
CMP  eax, ebx
JNE  they_are_different

; After SUB (ZF set if result = 0)
SUB  eax, 5
JNE  result_was_zero     ; JNE fires if eax was 5

; After TEST (check for zero / null)
TEST rdi, rdi
JNE  not_null             ; jump if rdi != 0

; While loop pattern
.while:
    CMP  ecx, 10
    JNE  .end_while
    ; ... body ...
    INC  ecx
    JMP  .while
.end_while:
```

## Notes

- JNE is functionally identical to its alias (JNZ) — same opcode, different mnemonic for readability.
- The jump range is ±2 GB in 64-bit mode (near jump).

## See Also

- [`CMP`](../Compare/CMP.md) — Compare (primary flag setter)
- [`TEST`](../Logic/TEST.md) — Non-destructive AND
- [`JMP`](./JMP.md) — Unconditional jump

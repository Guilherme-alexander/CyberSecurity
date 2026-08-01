# TEST — Logical Compare (Non-Destructive AND)

> This instruction also appears in the [Logic](../Logic/TEST.md) category. The full reference is there.

## Quick Reference

```asm
TEST operand1, operand2
```

Performs a bitwise AND, sets flags, **discards the result**. Commonly used before conditional jumps.

```asm
TEST eax, eax             ; check if eax == 0 (ZF) or negative (SF)
JZ   is_zero

TEST eax, 0x01            ; check if bit 0 is set
JNZ  is_odd

TEST rdi, rdi             ; null pointer check
JZ   null_ptr
```

See full documentation: [`../Logic/TEST.md`](../Logic/TEST.md)

## See Also

- [`CMP`](./CMP.md) — Non-destructive subtract (compare for order)
- [`AND`](../Logic/AND.md) — Destructive bitwise AND

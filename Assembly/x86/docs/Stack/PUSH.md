# PUSH — Push onto Stack

> Full documentation: [`../DataTransfer/PUSH.md`](../DataTransfer/PUSH.md)

## Quick Reference

```asm
PUSH rax                  ; RSP -= 8; [RSP] = rax
PUSH 42                   ; RSP -= 8; [RSP] = 42
PUSH qword [rbp-8]        ; push memory value
```

**Operation:** `RSP = RSP - operand_size; [RSP] = source`

Stack grows **downward**. Default size in 64-bit mode is 8 bytes.

## Common Prologue Pattern

```asm
my_function:
    PUSH rbp
    MOV  rbp, rsp
    SUB  rsp, 32
    ; ... body ...
    LEAVE
    RET
```

## See Also

- [`POP`](./POP.md) — Counterpart
- [`CALL`](./CALL.md) — Implicitly pushes return address
- [`DataTransfer/PUSH`](../DataTransfer/PUSH.md) — Full documentation

# POP — Pop from Stack

> Full documentation: [`../DataTransfer/POP.md`](../DataTransfer/POP.md)

## Quick Reference

```asm
POP rax                   ; rax = [RSP]; RSP += 8
POP qword [rbp-8]         ; pop into memory
```

**Operation:** `destination = [RSP]; RSP = RSP + operand_size`

## Common Epilogue Pattern

```asm
    ; ... function body ...
    POP rbp
    RET
    ; or equivalently:
    LEAVE
    RET
```

## See Also

- [`PUSH`](./PUSH.md) — Counterpart
- [`RET`](./RET.md) — Implicitly pops return address
- [`DataTransfer/POP`](../DataTransfer/POP.md) — Full documentation

# SAL — Shift Arithmetic Left

> **Note:** SAL and SHL are the **same instruction** — identical opcodes with different mnemonics. See [`SHL`](./SHL.md) for full documentation.

## Quick Reference

```asm
SAL destination, count    ; identical to SHL
```

Both shift bits left, filling vacated bits with **0**. The convention is:
- `SHL` — used for **unsigned** (logical) left shift
- `SAL` — used for **signed** (arithmetic) left shift

In practice the assembler emits the same bytes either way.

## See Also

- [`SHL`](./SHL.md) — Full documentation (same instruction)
- [`SAR`](./SAR.md) — Arithmetic right shift (not the same as SHR)

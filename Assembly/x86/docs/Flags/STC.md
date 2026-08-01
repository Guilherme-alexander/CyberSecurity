# STC — Set Carry Flag

## Syntax

```asm
STC
```

## Description

Sets the Carry Flag (CF) to 1.

## Flags Affected

**CF = 1**. No other flags are modified.

## Examples

```asm
; Shift a 1-bit into the MSB via RCR
STC
RCR  eax, 1               ; bit 31 of eax = 1 (from CF)

; Signal error via CF (DOS/BIOS convention)
STC                       ; CF=1 = error condition
RET                       ; caller checks JC/JNC

; Multi-precision subtract with initial borrow
STC                       ; treat as "borrow = 1" to start
SBB  rax, rbx
SBB  rdx, rcx
```

## Notes

- STC is a 1-byte instruction (`0xF9`).
- Some legacy APIs (DOS INT 21h, BIOS INT 13h) return CF=1 for error, CF=0 for success.

## See Also

- [`CLC`](./CLC.md) — Clear Carry Flag
- [`CMC`] — Complement Carry Flag
- [`SBB`] — Subtract with Borrow

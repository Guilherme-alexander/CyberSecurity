# CLC — Clear Carry Flag

## Syntax

```asm
CLC
```

## Description

Clears the Carry Flag (CF) to 0. Used to initialize CF before multi-precision arithmetic or rotation operations that depend on CF.

## Flags Affected

**CF = 0**. No other flags are modified.

## Examples

```asm
; Initialize before multi-precision addition chain
CLC
ADC  rax, rbx             ; add without initial carry
ADC  rdx, rcx             ; propagate carry

; Ensure CF=0 before RCL (rotate through carry)
CLC
RCL  eax, 1               ; shift in 0 from CF

; Explicit carry clear before ADCX chain (multi-precision)
CLC
ADCX rax, r8
ADCX rbx, r9
ADCX rcx, r10
```

## Notes

- CLC is a 1-byte instruction (`0xF8`) with zero latency on modern CPUs.
- Opposite of `STC` (Set Carry Flag).

## See Also

- [`STC`](./STC.md) — Set Carry Flag
- [`CMC`] — Complement (toggle) Carry Flag
- [`ADC`] — Add with Carry
- [`RCL`](../Shift/RCL.md) / [`RCR`](../Shift/RCR.md) — Rotate through Carry

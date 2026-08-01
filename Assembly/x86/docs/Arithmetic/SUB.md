# SUB — Subtract

## Syntax

```asm
SUB destination, source
```

## Description

Subtracts `source` from `destination` and stores the result in `destination`. Equivalent to `destination = destination - source`.

## Flags Affected

| Flag | Effect |
|------|--------|
| CF   | Set if unsigned borrow (result wrapped) |
| OF   | Set if signed overflow |
| ZF   | Set if result = 0 |
| SF   | Set to sign bit of result |
| PF   | Set if low byte has even parity |
| AF   | Set if borrow from bit 4 |

## Examples

```asm
; Register - Immediate
SUB eax, 5                ; eax = eax - 5

; Register - Register
SUB eax, ebx              ; eax = eax - ebx

; Memory - Register
SUB [rbp-4], eax

; Allocate stack space (subtract from RSP)
SUB rsp, 32               ; reserve 32 bytes for local variables

; Check for unsigned underflow (borrow)
SUB eax, ebx
JC  underflow             ; CF=1 means unsigned borrow occurred

; Check for zero result
SUB eax, ebx
JZ  they_are_equal        ; ZF=1 means eax == ebx
```

## Zeroing a Register

```asm
; SUB eax, eax is a classic idiom but XOR is preferred (faster/smaller)
SUB  eax, eax             ; eax = 0 (sets ZF, clears CF and OF)
XOR  eax, eax             ; eax = 0 (preferred: shorter encoding)
```

## Multi-Precision Subtraction

```asm
; 128-bit subtraction stored in [rbx:rax] - [rdx:rcx]
SUB  rax, rcx             ; subtract low halves
SBB  rbx, rdx             ; subtract high halves with borrow
```

## Notes

- `SUB dst, src` is used to implement `CMP`: CMP performs SUB but **discards** the result.
- To check if `a == b`: `SUB eax, ebx` → test ZF.
- `SUB eax, eax` sets ZF=1, CF=0, OF=0, and zeros the register.

## See Also

- [`ADD`](./ADD.md) — Add
- [`DEC`](./DEC.md) — Decrement (SUB by 1, without touching CF)
- [`CMP`](../Compare/CMP.md) — Compare (SUB that discards result)
- [`SBB`] — Subtract with borrow (multi-precision)
- [`NEG`](./NEG.md) — Two's complement negation

# CMP — Compare

## Syntax

```asm
CMP operand1, operand2
```

## Description

Subtracts `operand2` from `operand1` and **discards the result** — only the flags are updated. The operands are left unchanged. Use CMP before conditional jumps or SETcc.

## Flags Affected

| Flag | Effect |
|------|--------|
| CF   | Set if unsigned borrow (operand1 < operand2 unsigned) |
| OF   | Set if signed overflow |
| ZF   | Set if operands are equal (result = 0) |
| SF   | Set to sign bit of result |
| PF   | Updated |
| AF   | Updated |

## Examples

```asm
; Compare and branch
CMP eax, ebx
JE  equal                 ; jump if eax == ebx (ZF=1)
JNE not_equal             ; jump if eax != ebx (ZF=0)
JL  less                  ; jump if eax < ebx  (signed)
JG  greater               ; jump if eax > ebx  (signed)
JB  below                 ; jump if eax < ebx  (unsigned)
JA  above                 ; jump if eax > ebx  (unsigned)

; Compare with immediate
CMP eax, 0
JZ  is_zero

CMP eax, 100
JGE at_least_100

; Compare with memory
CMP eax, [rbp-4]
JLE skip

; String/char comparison
CMP al, 'A'
JB  not_uppercase
CMP al, 'Z'
JA  not_uppercase
; al is an uppercase letter

; Array bounds check
CMP rcx, ARRAY_SIZE
JAE out_of_bounds          ; unsigned: handles negative indices too
```

## Signed vs Unsigned Comparisons

```asm
; Signed comparisons — use JL/JLE/JG/JGE
CMP eax, ebx
JL  signed_less           ; -1 < 1 is TRUE

; Unsigned comparisons — use JB/JBE/JA/JAE
CMP eax, ebx
JB  unsigned_below        ; 0xFFFFFFFF > 1 (unsigned), not less
```

## CMP vs SUB vs TEST

```asm
; CMP: non-destructive SUB — only flags change
CMP eax, 5                ; flags set as if eax - 5, eax unchanged

; SUB: destructive — eax changes
SUB eax, 5                ; eax = eax - 5, flags set

; TEST: non-destructive AND — for zero/bit checks
TEST eax, eax             ; preferred way to check eax == 0
```

## Notes

- `CMP eax, 0` and `TEST eax, eax` produce the same ZF/SF, but TEST is a smaller encoding and preferred by compilers for checking zero.
- The order of operands matters: `CMP a, b` means `a - b`, so `CMP eax, 5; JL` checks `eax < 5`.

## See Also

- [`TEST`](../Logic/TEST.md) — Non-destructive AND (for zero/bit checks)
- [`SUB`](../Arithmetic/SUB.md) — Subtract (destructive)
- [`SETcc`](./SETcc.md) — Set byte based on condition
- Conditional jumps: [`JE`](../Jump/JE.md), [`JL`](../Jump/JL.md), [`JG`](../Jump/JG.md)

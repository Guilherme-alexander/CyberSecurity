# TEST — Logical Compare (Non-Destructive AND)

## Syntax

```asm
TEST operand1, operand2
```

## Description

Performs a bitwise AND of the two operands and **discards the result** — only the flags are updated. Used to test bits or check for zero without modifying either operand.

## Flags Affected

| Flag | Effect |
|------|--------|
| CF   | Cleared to 0 |
| OF   | Cleared to 0 |
| ZF   | Set if result = 0 |
| SF   | Set to sign bit of result |
| PF   | Updated |
| AF   | Undefined |

## Examples

```asm
; Test if register is zero
TEST eax, eax             ; sets ZF=1 if eax == 0
JZ   is_zero
JNZ  not_zero

; Test if a specific bit is set
TEST eax, 0x01            ; check bit 0 (odd/even)
JZ   is_even
JNZ  is_odd

TEST eax, (1 << 7)        ; check bit 7 (sign bit in low byte)
JNZ  bit7_set

; Test register for NULL (pointer check)
TEST rax, rax
JZ   null_pointer

; Check if value is negative (test sign bit)
TEST eax, eax
JS   is_negative          ; SF=1 if bit 31 is set

; Multiple bit check (are ANY of these bits set?)
TEST eax, 0b00001111      ; any of low 4 bits set?
JNZ  at_least_one_set

; Check a memory flag byte
TEST byte [flags], FLAG_ENABLED
JZ   flag_is_off
```

## TEST vs AND vs CMP

```asm
; TEST: non-destructive bit check (preferred for pure flag-checking)
TEST eax, mask            ; flags set, eax unchanged

; AND: destructive — updates eax AND sets flags
AND  eax, mask            ; eax &= mask (eax is modified)

; CMP: non-destructive subtraction check
CMP  eax, 0               ; flags from eax-0, eax unchanged
JZ   is_zero              ; same result as TEST eax, eax
; (TEST eax, eax is usually preferred over CMP eax, 0 — smaller encoding)
```

## Common Idiom: Return Value Check

```asm
CALL some_function        ; return value in eax
TEST eax, eax
JZ   function_returned_null_or_zero
JS   function_returned_negative
; otherwise: positive non-zero return
```

## Notes

- `TEST eax, eax` is the canonical way to check for zero or negative values — compilers emit this constantly.
- TEST cannot have two memory operands.
- Since TEST clears CF and OF, it can be used to explicitly reset those flags.

## See Also

- [`AND`](./AND.md) — Bitwise AND (destructive — modifies destination)
- [`CMP`](../Compare/CMP.md) — Compare (non-destructive SUB for flags)
- [`JZ`](../Jump/JE.md) / [`JNZ`](../Jump/JNE.md) — Jump on zero/not-zero

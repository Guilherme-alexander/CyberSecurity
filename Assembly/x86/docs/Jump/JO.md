# JO / JNO — Jump if Overflow / Jump if No Overflow

## Syntax

```asm
JO  label   ; Jump if Overflow Flag set (OF=1)
JNO label   ; Jump if No Overflow (OF=0)
```

## Description

`JO` fires when signed arithmetic overflow occurred (OF=1). Useful for detecting that a signed result exceeded the representable range.

## Examples

```asm
; Detect signed integer overflow after ADD
ADD  eax, ebx
JO   signed_overflow      ; result didn't fit in signed 32-bit

; Safe signed addition with overflow check
MOV  eax, INT32_MAX       ; 0x7FFFFFFF
ADD  eax, 1               ; overflow!
JO   handle_overflow      ; OF=1, jump

; Detect overflow after NEG
NEG  eax
JO   was_int_min          ; NEG of INT_MIN overflows

; After IMUL
IMUL eax, ebx
JO   product_overflow     ; product > 32-bit signed range
```

## Notes

- OF is distinct from CF: CF tracks **unsigned** overflow, OF tracks **signed** overflow.
- After `ADD 127 + 1` (8-bit): CF=0 (no unsigned overflow), OF=1 (signed overflow).
- After `ADD 200 + 200` (8-bit unsigned as 255+max): CF=1, OF=0.

## See Also

- [`JC`](./JC.md) — Jump if Carry (unsigned overflow)
- [`ADD`](../Arithmetic/ADD.md) — Sets OF on signed overflow
- [`IMUL`](../Arithmetic/IMUL.md) — Sets OF when result is truncated

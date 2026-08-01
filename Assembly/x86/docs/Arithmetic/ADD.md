# ADD — Add

## Syntax

```asm
ADD destination, source
```

## Description

Adds `source` to `destination` and stores the result in `destination`. Updates EFLAGS to reflect the result.

## Flags Affected

| Flag | Effect |
|------|--------|
| CF   | Set if unsigned overflow (carry out of MSB) |
| OF   | Set if signed overflow |
| ZF   | Set if result = 0 |
| SF   | Set to sign bit of result |
| PF   | Set if low byte has even parity |
| AF   | Set if carry from bit 3 to bit 4 (BCD) |

## Examples

```asm
; Register + Immediate
ADD eax, 10               ; eax = eax + 10

; Register + Register
ADD eax, ebx              ; eax = eax + ebx

; Memory + Register
ADD [rbp-4], eax          ; [rbp-4] = [rbp-4] + eax

; Register + Memory
ADD eax, [rbx]            ; eax = eax + *rbx

; 64-bit addition
ADD rax, rdi              ; rax = rax + rdi

; Unsigned overflow check
ADD eax, ebx
JC  overflow_handler      ; jump if carry flag set (unsigned overflow)

; Signed overflow check
ADD eax, ebx
JO  overflow_handler      ; jump if overflow flag set (signed overflow)
```

## Common Patterns

```asm
; Increment by 1 (prefer INC for code size, but ADD for flag behavior)
ADD eax, 1                ; sets CF unlike INC

; Array pointer advance
ADD rsi, 4                ; move to next int element (4 bytes)
ADD rsi, 8                ; move to next int64 element (8 bytes)

; Loop counter
ADD rcx, 1
CMP rcx, rax
JL  .loop

; Multi-precision addition (128-bit from two 64-bit values)
ADD  rax, rdx             ; add low halves
ADC  rbx, rcx             ; add high halves + carry
```

## Notes

- `ADD eax, 1` and `INC eax` differ: ADD sets CF, INC does **not** affect CF.
- For address arithmetic that should not change flags, use `LEA`.
- The destination can be register or memory, but not both memory operands simultaneously.

## See Also

- [`SUB`](./SUB.md) — Subtract
- [`INC`](./INC.md) — Increment (ADD by 1 without touching CF)
- [`ADC`](./ADD.md) — Add with carry (for multi-precision)
- [`LEA`](../DataTransfer/LEA.md) — Flag-free address arithmetic

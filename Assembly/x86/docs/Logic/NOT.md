# NOT — Bitwise NOT (One's Complement)

## Syntax

```asm
NOT destination
```

## Description

Inverts every bit of `destination` (one's complement). Equivalent to `XOR destination, 0xFFFFFFFF` (for 32-bit).

## Flags Affected

**None.** NOT does not modify EFLAGS at all.

## Examples

```asm
; Invert all bits
MOV eax, 0                ; eax = 0x00000000
NOT eax                   ; eax = 0xFFFFFFFF

MOV eax, 0xFF             ; eax = 0x000000FF
NOT eax                   ; eax = 0xFFFFFF00

; NOT in memory
NOT dword [rbp-4]

; Build mask complement
MOV eax, MASK
NOT eax                   ; eax = ~MASK (inverted mask)
AND ebx, eax              ; clear those bits in ebx

; NOT + ADD = NEG (two's complement from one's complement)
NOT eax                   ; one's complement
ADD eax, 1                ; two's complement = NEG eax
```

## NOT vs NEG

```asm
; NOT: one's complement (flip all bits, NO +1)
MOV eax, 5                ; 0x00000005
NOT eax                   ; 0xFFFFFFA (= -6 signed, not -5!)

; NEG: two's complement (flip all bits THEN add 1)
MOV eax, 5                ; 0x00000005
NEG eax                   ; 0xFFFFFFFB (= -5 signed — correct negation)
```

## Bitwise Complement for Masks

```asm
; Clear bits defined by a mask
AND rsp, ~0xF             ; align to 16 bytes (assembler evaluates ~0xF = 0xFFFFFFF0)
; In runtime code when mask is in a register:
MOV ecx, 0xF
NOT ecx                   ; ecx = 0xFFFFFFF0
AND rsp, rcx
```

## Notes

- NOT is the only logical instruction that **doesn't affect flags**.
- It is a single-operand instruction; the operand can be a register or memory location.
- `NOT eax` followed by `ADD eax, 1` equals `NEG eax`.

## See Also

- [`NEG`](../Arithmetic/NEG.md) — Two's complement negate (NOT + 1)
- [`XOR`](./XOR.md) — XOR with 0xFF…FF achieves the same effect
- [`AND`](./AND.md) — Bitwise AND

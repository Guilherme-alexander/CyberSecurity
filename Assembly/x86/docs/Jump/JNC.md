# JNC / JAE — Jump if No Carry / Jump if Above or Equal (Unsigned)

## Syntax

```asm
JNC label   ; Jump if No Carry (CF=0)
JAE label   ; Jump if Above or Equal (unsigned >=) — same opcode
JNB label   ; Jump if Not Below — same opcode
```

## Description

Jumps when **CF=0**. After unsigned `CMP a, b`: CF=0 means `a >= b` (unsigned).

## Examples

```asm
; Unsigned greater-or-equal check
CMP  eax, MIN_VALUE
JAE  at_least_min         ; jump if eax >= MIN_VALUE (unsigned)

; No carry after addition
ADD  eax, ebx
JNC  no_overflow          ; CF=0: result fit in 32 bits

; Check shift didn't lose a bit
SHR  eax, 1
JNC  bit_was_zero         ; the shifted-out bit was 0
JC   bit_was_one          ; the shifted-out bit was 1
```

## See Also

- [`JC`](./JC.md) — Jump if Carry (opposite)
- [`JGE`](./JGE.md) — Signed equivalent (above or equal)

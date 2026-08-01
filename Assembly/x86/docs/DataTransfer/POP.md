# POP — Pop from Stack

## Syntax

```asm
POP destination
```

## Description

Reads the value at the current top of the stack into `destination`, then increments the stack pointer (RSP/ESP) by the operand size.

## Operation

```
destination = [RSP]
RSP = RSP + operand_size
```

## Flags Affected

None (RSP is modified, but EFLAGS are not).

## Examples

```asm
; Pop into register
POP rax                   ; rax = [RSP]; RSP += 8

; Pop into memory
POP qword [rbp-8]         ; [rbp-8] = [RSP]; RSP += 8

; Restore multiple registers (in reverse PUSH order)
PUSH rax
PUSH rbx
PUSH rcx
; ... some code ...
POP  rcx
POP  rbx
POP  rax
```

## Function Epilogue Pattern

```asm
my_function:
    PUSH rbp
    MOV  rbp, rsp
    SUB  rsp, 32
    ; ... function body ...
    ; Epilogue:
    MOV  rsp, rbp         ; discard locals
    POP  rbp              ; restore caller's frame
    RET
    ; Equivalent shorthand: LEAVE + RET
```

## Discarding the Top of Stack

```asm
; If you just want to remove a value without using it:
ADD rsp, 8                ; skip 8 bytes (faster than POP into a throwaway reg)

; Or pop into a scratch register
POP rax                   ; rax gets the discarded value
```

## Notes

- In 64-bit mode, POP always pops 8 bytes by default.
- `POP rsp` is legal and sets RSP to the value that was on the stack.
- Popping the wrong number of bytes leads to a corrupted stack and likely a crash — always pair PUSHes and POPs carefully.
- Avoid POPing into segment registers (`POP ds`, `POP es`, etc.) in user-mode 64-bit code; it's rarely valid outside OS kernels.

## See Also

- [`PUSH`](./PUSH.md) — Push onto stack
- [`RET`](../Stack/RET.md) — Return (implicitly POPs the return address)
- [`LEAVE`](../Stack/LEAVE.md) — Restore frame and pop base pointer

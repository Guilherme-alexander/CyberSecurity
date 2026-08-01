# CALL — Call Subroutine

## Syntax

```asm
CALL target        ; direct call
CALL reg           ; indirect call via register
CALL [mem]         ; indirect call via memory
```

## Description

Pushes the **return address** (the address of the next instruction) onto the stack, then jumps to `target`. The matching `RET` instruction pops the return address and resumes execution.

## Operation

```
RSP = RSP - 8           ; (or -4 in 32-bit mode)
[RSP] = RIP             ; push return address
RIP = target            ; jump to callee
```

## Flags Affected

None.

## Examples

```asm
; Direct call by label
CALL my_function

; Indirect call via register (function pointer)
MOV  rax, [function_ptr]
CALL rax

; Indirect call via memory
CALL [dispatch_table + rcx*8]

; Typical function call (System V AMD64 ABI)
MOV  rdi, arg1            ; first integer argument
MOV  rsi, arg2            ; second integer argument
MOV  rdx, arg3            ; third
XOR  eax, eax             ; AL = 0: no SSE arguments (variadic functions)
CALL printf

; Stack must be 16-byte aligned BEFORE the CALL
; (CALL itself pushes 8 bytes, making RSP 16-byte aligned inside callee)
AND  rsp, ~0xF            ; align if unsure
CALL some_function
```

## Calling Convention Overview (System V AMD64)

| Purpose | Registers |
|---------|-----------|
| Integer args (in order) | RDI, RSI, RDX, RCX, R8, R9 |
| Return value | RAX (RDX for 128-bit) |
| Caller-saved (scratch) | RAX, RCX, RDX, RSI, RDI, R8–R11 |
| Callee-saved | RBX, RBP, R12–R15 |

## Nested Calls

```asm
outer:
    PUSH rbp
    MOV  rbp, rsp
    SUB  rsp, 16          ; space for locals + alignment

    MOV  rdi, 42
    CALL inner            ; inner's return address pushed here

    ; eax now holds return value from inner
    ADD  rsp, 16
    POP  rbp
    RET

inner:
    PUSH rbp
    MOV  rbp, rsp
    ; rdi = 42 here
    MOV  eax, edi
    IMUL eax, 2           ; return rdi * 2
    POP  rbp
    RET
```

## Notes

- In 64-bit mode, CALL always pushes 8 bytes (the full RIP).
- The stack must be **16-byte aligned** before a CALL in the System V ABI (the OS X ABI requires this too).
- Tail-call optimization replaces `CALL; RET` with `JMP` when the callee's result is immediately returned.

## See Also

- [`RET`](./RET.md) — Return from subroutine
- [`PUSH`](../DataTransfer/PUSH.md) / [`POP`](../DataTransfer/POP.md) — Stack operations
- [`LEAVE`](./LEAVE.md) — Frame teardown helper

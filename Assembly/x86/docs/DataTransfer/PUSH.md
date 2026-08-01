# PUSH — Push onto Stack

## Syntax

```asm
PUSH source
```

## Description

Decrements the stack pointer (RSP/ESP) by the operand size, then writes `source` to the new top of the stack. In 64-bit mode the default operand size is 64 bits (8 bytes).

## Operation

```
RSP = RSP - operand_size
[RSP] = source
```

## Flags Affected

None (RSP is modified, but EFLAGS are not).

## Examples

```asm
; Push a register
PUSH rax                  ; RSP -= 8; [RSP] = rax

; Push an immediate
PUSH 42                   ; RSP -= 8; [RSP] = 42

; Push memory
PUSH qword [rbp-8]        ; push 64-bit value from stack frame

; Push all general-purpose registers (legacy PUSHA — 32-bit only)
; In 64-bit mode, save registers individually:
PUSH rax
PUSH rbx
PUSH rcx
PUSH rdx

; Corresponding POPs in reverse order
POP  rdx
POP  rcx
POP  rbx
POP  rax
```

## Function Prologue Pattern

```asm
my_function:
    PUSH rbp              ; save caller's base pointer
    MOV  rbp, rsp         ; establish new frame
    SUB  rsp, 32          ; allocate 32 bytes for locals
    ; ... function body ...
    LEAVE                 ; MOV rsp, rbp  +  POP rbp
    RET
```

## Callee-Saved Registers (System V AMD64 ABI)

```asm
my_function:
    PUSH rbp
    PUSH rbx              ; callee-saved: must preserve rbx, r12-r15
    PUSH r12
    PUSH r13
    ; ... use rbx, r12, r13 freely ...
    POP  r13
    POP  r12
    POP  rbx
    POP  rbp
    RET
```

## Notes

- In **64-bit mode**, PUSH always uses 8-byte (64-bit) chunks; you cannot push 32-bit values directly.
- You **can** push 16-bit values with an operand-size prefix (`PUSH ax`), but this misaligns the stack and is rarely done.
- The stack grows **downward**: each PUSH subtracts from RSP.
- Keep RSP **16-byte aligned** before a `CALL` (System V ABI requirement).

## See Also

- [`POP`](./POP.md) — Pop from stack
- [`CALL`](../Stack/CALL.md) — Call subroutine (implicitly pushes return address)
- [`RET`](../Stack/RET.md) — Return from subroutine
- [`ENTER`](../Stack/ENTER.md) / [`LEAVE`](../Stack/LEAVE.md) — Frame setup/teardown

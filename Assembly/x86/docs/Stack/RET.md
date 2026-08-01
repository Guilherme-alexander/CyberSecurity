# RET — Return from Subroutine

## Syntax

```asm
RET              ; near return
RET imm16        ; near return + pop imm16 bytes from stack
RETF             ; far return (pops CS:IP)
```

## Description

Pops the return address from the top of the stack and jumps to it, transferring control back to the caller.

## Operation

```
RIP = [RSP]        ; load return address
RSP = RSP + 8      ; pop it off stack
; if RET imm16:
RSP = RSP + imm16  ; also clean up stack arguments
```

## Flags Affected

None.

## Examples

```asm
; Simple return
my_function:
    MOV eax, 42           ; return value in EAX
    RET

; Return with stack cleanup (stdcall / Windows convention)
; Callee cleans up N bytes of arguments
my_stdcall_func:
    ; ... use [rbp+8], [rbp+12] (32-bit stack args) ...
    RET 8                 ; pop 2 dwords pushed by caller

; Multiple return paths
check_value:
    PUSH rbp
    MOV  rbp, rsp
    CMP  eax, 0
    JL   .negative
    MOV  eax, 1           ; positive: return 1
    POP  rbp
    RET
.negative:
    MOV  eax, -1          ; negative: return -1
    POP  rbp
    RET

; Tail call optimization: replace CALL + RET with JMP
; Instead of:
;   CALL other_func
;   RET
; Write:
    JMP  other_func       ; saves a CALL/RET pair, same effect
```

## Stack State on RET

```
Before RET:              After RET:
RSP -> [return address]  RSP -> [caller's next item]
       [caller's data]   RIP  = return address
```

## Notes

- `RET imm16` is used in **stdcall** (Windows API) where the callee cleans up stack-passed arguments.
- In the System V AMD64 ABI (Linux/macOS), arguments are in registers — `RET` with no operand is almost always used.
- A mismatched PUSH/POP corrupts the return address → crash.
- `RET` is essentially `POP RIP`.

## See Also

- [`CALL`](./CALL.md) — Call subroutine (pushes return address)
- [`LEAVE`](./LEAVE.md) — Frame teardown (restores RSP and RBP before RET)
- [`PUSH`](../DataTransfer/PUSH.md) / [`POP`](../DataTransfer/POP.md)

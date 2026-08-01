# LEAVE — Destroy Stack Frame

## Syntax

```asm
LEAVE
```

## Description

Tears down the current stack frame. Equivalent to:

```asm
MOV rsp, rbp    ; discard local variables (restore RSP to saved value)
POP rbp         ; restore caller's base pointer
```

Always used before `RET` when a frame was established with `PUSH rbp; MOV rbp, rsp`.

## Flags Affected

None.

## Examples

```asm
; Standard function epilogue
my_function:
    PUSH rbp              ; prologue
    MOV  rbp, rsp
    SUB  rsp, 32          ; 32 bytes of locals

    ; ... function body using [rbp-4], [rbp-8], etc. ...

    MOV  eax, 42          ; return value
    LEAVE                 ; MOV rsp, rbp + POP rbp
    RET

; Equivalent explicit epilogue:
    MOV  rsp, rbp
    POP  rbp
    RET

; Multiple exit points all use LEAVE
check_positive:
    PUSH rbp
    MOV  rbp, rsp
    TEST eax, eax
    JNS  .ok
    MOV  eax, 0
    LEAVE
    RET
.ok:
    LEAVE
    RET
```

## Notes

- LEAVE is a **single-byte instruction** (0xC9) — compact epilogue.
- It restores RSP from RBP, so even if RSP was modified inside the function, LEAVE correctly discards the frame.
- On modern CPUs, LEAVE is usually as fast as the two-instruction equivalent.

## See Also

- [`ENTER`](./ENTER.md) — Create stack frame (counterpart)
- [`RET`](./RET.md) — Return (follows LEAVE)
- [`PUSH`](../DataTransfer/PUSH.md) / [`POP`](../DataTransfer/POP.md)

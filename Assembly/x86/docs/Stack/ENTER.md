# ENTER — Create Stack Frame

## Syntax

```asm
ENTER locals, nesting
```

- `locals` — bytes to allocate for local variables (16-bit immediate)
- `nesting` — lexical nesting level (0 for most use cases)

## Description

Sets up a stack frame for a procedure. `ENTER n, 0` is equivalent to:

```asm
PUSH rbp
MOV  rbp, rsp
SUB  rsp, n
```

## Flags Affected

None.

## Examples

```asm
; Allocate 32 bytes for locals (nesting = 0, most common)
my_function:
    ENTER 32, 0
    ; rbp is set up; [rbp-4] to [rbp-32] are local variables
    ; ... function body ...
    LEAVE
    RET

; Equivalent manual prologue (preferred by compilers):
my_function:
    PUSH rbp
    MOV  rbp, rsp
    SUB  rsp, 32
    ; ... function body ...
    MOV  rsp, rbp
    POP  rbp
    RET
```

## Notes

- `ENTER` is **rarely used by modern compilers** because it is slower than the equivalent 3-instruction prologue on modern CPUs.
- `nesting > 0` creates a display (chain of frame pointers for nested procedures) — a Pascal/Algol feature almost never used in C/ASM.
- Always pair with `LEAVE`.

## See Also

- [`LEAVE`](./LEAVE.md) — Destroy stack frame (counterpart to ENTER)
- [`PUSH`](../DataTransfer/PUSH.md) / [`POP`](../DataTransfer/POP.md)
- [`CALL`](./CALL.md) / [`RET`](./RET.md)

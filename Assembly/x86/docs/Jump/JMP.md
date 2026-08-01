# JMP — Unconditional Jump

## Syntax

```asm
JMP target
```

## Description

Transfers execution unconditionally to `target`. The target can be a label, register, or memory location (indirect jump).

## Jump Forms

| Form | Description |
|------|-------------|
| `JMP label` | Short/near direct jump to label |
| `JMP reg` | Indirect jump to address in register |
| `JMP [mem]` | Indirect jump to address stored in memory |
| `JMP FAR ptr` | Far jump (changes CS:IP — rare in 64-bit) |

## Flags Affected

None.

## Examples

```asm
; Direct jump to label
JMP done
; ... code never reached ...
done:
    RET

; Infinite loop
.loop:
    ; ... do work ...
    JMP .loop

; Indirect jump via register (jump table / switch)
JMP rax                   ; jump to address in rax

; Jump table (switch statement)
section .data
    jump_table dq case0, case1, case2, case3

section .text
    CMP ecx, 3
    JA  default_case       ; bounds check
    MOV rax, [jump_table + rcx*8]
    JMP rax                ; dispatch

case0: ; handle 0
    JMP end_switch
case1: ; handle 1
    JMP end_switch
case2: ; handle 2
    JMP end_switch
case3: ; handle 3
end_switch:

; Skip a block of code
JMP .skip
    ; ... this code is bypassed ...
.skip:
```

## Short vs Near Jumps (Encoding)

| Type | Range | Bytes |
|------|-------|-------|
| Short | ±127 bytes | 2 |
| Near | ±2 GB | 5 |

Assemblers pick the smallest encoding automatically. Force short with `JMP SHORT label` if needed.

## Notes

- JMP is equivalent to `MOV rip, target` — it sets the instruction pointer.
- Indirect jumps (`JMP rax`) are fast but can cause branch target mispredictions.
- In 64-bit mode, far jumps are unusual and restricted.
- Loop constructs typically use conditional jumps at the bottom rather than JMP at the top.

## See Also

- [`JE`](./JE.md), [`JNE`](./JNE.md), [`JL`](./JL.md) — Conditional jumps
- [`CALL`](../Stack/CALL.md) — Jump and push return address
- [`RET`](../Stack/RET.md) — Return (indirect jump to stack top)
- [`LOOP`](./LOOP.md) — Loop with implicit counter

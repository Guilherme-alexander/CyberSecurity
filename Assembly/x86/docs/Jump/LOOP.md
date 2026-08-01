# LOOP — Loop with Counter

## Syntax

```asm
LOOP  label     ; Decrement CX/ECX/RCX, jump if != 0
LOOPE label     ; Loop while Equal (ZF=1 and count != 0)
LOOPNE label    ; Loop while Not Equal (ZF=0 and count != 0)
```

## Description

Decrements the count register (CX, ECX, or RCX depending on address size) and jumps to `label` if the result is **non-zero**. A concise counted loop in one instruction.

## Flags Affected

None (the count register is modified, but EFLAGS are not).

## Examples

```asm
; Sum of integers 1..10
XOR  eax, eax             ; sum = 0
MOV  ecx, 10             ; counter = 10
.loop:
    ADD  eax, ecx         ; sum += counter
    LOOP .loop            ; ECX--, jump if ECX != 0
; eax = 55

; Copy 8 bytes
MOV  ecx, 8
.copy:
    MOV  al, [rsi]
    MOV  [rdi], al
    INC  rsi
    INC  rdi
    LOOP .copy

; LOOPE: loop while equal AND count > 0
MOV  ecx, 100
.scan:
    SCASB                 ; compare AL with [RDI++], sets ZF
    LOOPE .scan           ; keep scanning while bytes match and ECX > 0

; LOOPNE: loop while not equal AND count > 0 (find first match)
MOV  ecx, 100
MOV  al, TARGET
.find:
    SCASB
    LOOPNE .find          ; stop when byte matches or count expires
```

## LOOP vs DEC+JNZ

```asm
; LOOP (1 instruction, but often slower on modern CPUs):
MOV ecx, N
.loop:
    ; ... body ...
    LOOP .loop

; DEC + JNZ (2 instructions, but faster on modern x86):
MOV ecx, N
.loop:
    ; ... body ...
    DEC ecx
    JNZ .loop
```

## Notes

- LOOP was fast on old x86 (8086/286) but on modern CPUs `DEC ecx; JNZ` is usually preferred — the CPU can fuse DEC+JNZ into a single micro-op.
- LOOP always uses ECX in 32-bit mode and RCX in 64-bit mode (with the REX prefix).
- LOOP range is only **±127 bytes** (short jump only) — for larger loops, use DEC+JNZ.
- If ECX starts at 0, LOOP wraps to 0xFFFFFFFF and runs ~4 billion iterations — always verify the counter.

## See Also

- [`DEC`](../Arithmetic/DEC.md) — Decrement (preferred loop counter)
- [`JNE`](./JNE.md) — Jump if not zero/equal
- [`SCAS`](../String/SCAS.md) — Scan string (used with LOOPE/LOOPNE)

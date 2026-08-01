# NOP — No Operation

## Syntax

```asm
NOP                  ; 1-byte NOP (0x90)
NOP [mem], reg       ; Multi-byte NOP (hint form)
```

## Description

Does nothing — consumes a clock cycle and instruction fetch bandwidth but has no effect on registers, memory, or flags. Used for alignment, timing pads, code patching, and as a breakpoint placeholder.

## Flags Affected

None.

## Examples

```asm
; Single-byte NOP (0x90)
NOP

; Align loop target to 16-byte boundary (assembler directive preferred)
ALIGN 16
.loop:
    ADD eax, ebx
    DEC ecx
    JNZ .loop

; Multi-byte NOPs for padding (NASM generates efficient encodings)
; Assemblers typically use:
; 2-byte: 66 90
; 3-byte: 0F 1F 00
; 4-byte: 0F 1F 40 00
; 7-byte: 0F 1F 84 00 00 00 00 00
; 9-byte: 66 0F 1F 84 00 00 00 00 00

; Patch a short JMP (2 bytes) with NOPs for hot-patching
; Before patch:
;   EB 05      JMP +5
; After patch:
;   90 90      NOP NOP (neutralized)

; Delay loop (ancient — use RDTSC or OS sleep in modern code)
MOV  ecx, 1000
.delay:
    NOP
    LOOP .delay

; Classic 1-byte NOP encoding trick
XCHG eax, eax            ; 0x90 — equivalent to NOP (historical)
```

## Multi-Byte NOPs

Modern x86 CPUs include multi-byte NOP encodings to avoid decoding multiple single-byte NOPs:

| Size | Bytes |
|------|-------|
| 1    | `90` |
| 2    | `66 90` |
| 3    | `0F 1F 00` |
| 4    | `0F 1F 40 00` |
| 5–9  | `0F 1F 84 00 ...` |

Use `TIMES n NOP` in NASM or compiler alignment directives — the assembler picks the best encoding.

## Notes

- `0x90` (`XCHG eax, eax`) is the traditional 1-byte NOP.
- NOPs consume decode/execute resources — for large pads, use multi-byte NOPs.
- Debuggers often temporarily replace instruction bytes with `0x90` to set software breakpoints (using `INT3` / `0xCC` is more standard now).

## See Also

- [`HLT`](./HLT.md) — Halt CPU
- [`RDTSC`](./RDTSC.md) — Read Time-Stamp Counter (for timing)
- [`INT`](./INT.md) — Software interrupt (INT3 = breakpoint)

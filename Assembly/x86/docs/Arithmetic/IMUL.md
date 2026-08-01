# IMUL — Signed Multiply

## Syntax

```asm
; One-operand form (like MUL, implicit accumulator)
IMUL source

; Two-operand form
IMUL destination, source

; Three-operand form
IMUL destination, source, immediate
```

## Description

Performs **signed** (two's complement) multiplication. IMUL has three forms — the two- and three-operand forms are more convenient for most uses and keep the result in a single register (truncated to the destination size).

## One-Operand Form — Implicit Accumulator

| Source | Multiplicand | Result |
|--------|-------------|--------|
| 8-bit  | AL          | AX     |
| 16-bit | AX          | DX:AX  |
| 32-bit | EAX         | EDX:EAX|
| 64-bit | RAX         | RDX:RAX|

CF and OF are set if the result doesn't fit in the lower half.

## Flags Affected

- **CF and OF**: Set if the result is truncated (two-operand/three-operand forms), or if upper half is non-zero (one-operand form).
- SF, ZF, PF, AF: **Undefined**.

## Examples

```asm
; --- One-operand form ---
MOV eax, -5
MOV ebx, 3
IMUL ebx                  ; EDX:EAX = -5 * 3 = -15

; --- Two-operand form: dst *= src ---
MOV eax, 10
IMUL eax, 7               ; eax = 10 * 7 = 70

IMUL eax, ebx             ; eax = eax * ebx
IMUL rax, rcx             ; rax = rax * rcx (64-bit)
IMUL eax, [rbp-4]         ; eax = eax * (memory value)

; --- Three-operand form: dst = src * imm ---
IMUL eax, ebx, 5          ; eax = ebx * 5
IMUL rax, rcx, 100        ; rax = rcx * 100

; Multiply by constant without clobbering source
IMUL ecx, eax, 3          ; ecx = eax * 3 (eax unchanged)

; Check for signed overflow in two-operand form
IMUL eax, ebx
JO   overflow_handler     ; OF=1: result truncated

; Fast multiply by non-power-of-2 constant
IMUL eax, ebx, 9          ; eax = ebx * 9 (one instruction!)
```

## Comparison with MUL

```asm
; Signed: IMUL with negative numbers
MOV eax, -4
IMUL eax, 3               ; eax = -12 (correct for signed)

; Unsigned: MUL with the same bit pattern
MOV eax, 0xFFFFFFFC       ; same bits as -4
MOV ecx, 3
MUL ecx                   ; EDX:EAX = 0x2FFFFFFF4 (unsigned result)
```

## Notes

- The **two- and three-operand forms** of IMUL produce the same truncated lower-half result as MUL for values that fit — they differ only for large results. Compilers often prefer IMUL for both signed and unsigned multiplications when only the lower bits matter.
- Three-operand `IMUL dst, src, imm` is ideal for applying a constant multiplier without touching the source.
- Performance: typically 3 cycles latency on modern x86.

## See Also

- [`MUL`](./MUL.md) — Unsigned multiply
- [`IDIV`](./IDIV.md) — Signed divide
- [`NEG`](./NEG.md) — Negate (multiply by -1)
- [`LEA`](../DataTransfer/LEA.md) — Multiply by 2/3/4/5/8/9 via addressing

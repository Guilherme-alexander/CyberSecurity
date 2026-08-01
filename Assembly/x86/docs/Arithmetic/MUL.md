# MUL — Unsigned Multiply

## Syntax

```asm
MUL source
```

## Description

Performs **unsigned** multiplication of the implicit accumulator register by `source`. The result is stored across two registers to accommodate the doubled width.

## Implicit Operands

| Source size | Implicit multiplicand | Result stored in |
|-------------|----------------------|-----------------|
| 8-bit       | AL                   | AX               |
| 16-bit      | AX                   | DX:AX            |
| 32-bit      | EAX                  | EDX:EAX          |
| 64-bit      | RAX                  | RDX:RAX          |

## Flags Affected

- **CF and OF**: Set if the upper half of the result is non-zero (i.e., result doesn't fit in the lower half).
- SF, ZF, PF, AF: **Undefined**.

## Examples

```asm
; 8-bit: AL * source -> AX
MOV al, 25
MOV bl, 10
MUL bl                    ; AX = 25 * 10 = 250
; AX = 250, CF=OF=0 (fits in AL)

; 32-bit: EAX * source -> EDX:EAX
MOV eax, 0xFFFFFFFF       ; 4,294,967,295
MOV ecx, 2
MUL ecx                   ; EDX:EAX = 8,589,934,590
; EDX = 1, EAX = 0xFFFFFFFE, CF=OF=1 (result spilled into EDX)

; 64-bit: RAX * source -> RDX:RAX
MOV rax, 0xFFFFFFFFFFFFFFFF
MOV rbx, 2
MUL rbx                   ; RDX:RAX = result
; Overflow check:
JC  overflow_handler      ; if CF=1, upper half in RDX is non-zero

; Unsigned division of 32-bit value by 3 via multiply (faster than DIV)
; n/3 approximated as (n * 0x55555556) >> 32
MOV  eax, [dividend]
MOV  ecx, 0x55555556
MUL  ecx                  ; EDX:EAX = eax * magic
; EDX now contains the quotient
```

## Check for Overflow

```asm
MUL rbx
JO  too_large             ; OF=1: result > 64 bits
; or equivalently:
JC  too_large             ; CF=1 same condition
```

## Notes

- MUL is the **unsigned** multiply; for **signed** use `IMUL`.
- The single-operand form always uses the accumulator implicitly.
- `IMUL` has flexible 2- and 3-operand forms that are often more convenient; MUL is strictly single-operand.
- Performance: MUL latency is typically 3–4 cycles on modern x86.

## See Also

- [`IMUL`](./IMUL.md) — Signed multiply (with 2/3-operand forms)
- [`DIV`](./DIV.md) — Unsigned divide
- [`SHL`](../Shift/SHL.md) — Multiply by power of 2

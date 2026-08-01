# MOVZX — Move with Zero-Extension

## Syntax

```asm
MOVZX destination, source
```

## Description

Copies `source` into `destination`, **zero-extending** by filling all upper bits with 0. Use this for **unsigned** integers when promoting to a larger type.

## Flags Affected

None.

## Examples

```asm
; 8-bit -> 16-bit zero extension
MOVZX ax, bl              ; if bl = 0xFF (255), ax = 0x00FF (255)

; 8-bit -> 32-bit zero extension
MOVZX eax, bl             ; if bl = 0xFF, eax = 0x000000FF = 255

; 16-bit -> 32-bit zero extension
MOVZX eax, bx             ; if bx = 0xFFFF, eax = 0x0000FFFF = 65535

; From memory
MOVZX eax, byte [rbp-1]   ; load unsigned byte, zero-extend to 32-bit
MOVZX eax, word [rsi]     ; load unsigned word from pointer in rsi
```

## Zero Extension vs Sign Extension

```asm
; Source byte: 0x80 = 128 unsigned, -128 signed

MOVZX eax, bl             ; eax = 0x00000080 = 128  (unsigned interpretation)
MOVSX eax, bl             ; eax = 0xFFFFFF80 = -128 (signed interpretation)
```

## 64-bit Implicit Zero Extension

```asm
; In 64-bit mode, a 32-bit MOV already zero-extends to 64 bits:
MOV eax, 42               ; rax = 0x000000000000002A (implicit)

; So MOVZX into 32-bit destination also zero-extends rax:
MOVZX eax, bl             ; rax upper 32 bits are also cleared
```

## Practical: Parsing a Byte Array as Unsigned

```asm
; Loop summing unsigned bytes
XOR  eax, eax             ; sum = 0
XOR  ecx, ecx             ; i = 0
.loop:
    MOVZX edx, byte [rbx + rcx]  ; edx = (unsigned)array[i]
    ADD   eax, edx
    INC   ecx
    CMP   ecx, 16
    JL    .loop
```

## Notes

- No 32-bit → 64-bit form of `MOVZX` exists; just use `MOV eax, eax` (or any MOV into a 32-bit register) because x86-64 implicitly zero-extends.
- Prefer `MOVZX` over masking with AND for clarity and code size.
- The source can be a register or memory; the destination must be a register.

## See Also

- [`MOVSX`](./MOVSX.md) — Move with sign-extension (for signed integers)
- [`MOV`](./MOV.md) — Same-size move
- [`AND`](../Logic/AND.md) — Bitwise AND (alternative masking approach)

# MOVSX — Move with Sign-Extension

## Syntax

```asm
MOVSX destination, source
MOVSXD destination, source   ; 64-bit variant for 32->64
```

## Description

Copies `source` into `destination`, **sign-extending** the value to fill the larger destination. Sign-extension replicates the most-significant bit (the sign bit) of the source into all upper bits of the destination. Use this for signed integers.

## Flags Affected

None.

## Examples

```asm
; 8-bit -> 16-bit sign extension
MOVSX ax, bl              ; if bl = 0xFF (-1 signed), ax = 0xFFFF (-1)
MOVSX ax, bl              ; if bl = 0x7F (+127),      ax = 0x007F (+127)

; 8-bit -> 32-bit sign extension
MOVSX eax, bl             ; if bl = 0x80 (-128), eax = 0xFFFFFF80

; 16-bit -> 32-bit sign extension
MOVSX eax, bx             ; if bx = 0x8000 (-32768), eax = 0xFFFF8000

; From memory
MOVSX eax, byte [rbp-1]   ; load signed byte, extend to 32-bit
MOVSX eax, word [rbp-2]   ; load signed word, extend to 32-bit

; 32-bit -> 64-bit (use MOVSXD)
MOVSXD rax, eax           ; sign-extend 32-bit eax into 64-bit rax
MOVSXD rax, dword [rbp-4] ; load signed dword, extend to 64-bit
```

## Sign Extension vs Zero Extension

```asm
; Source value: 0xFF = 255 unsigned, -1 signed (8-bit)

; MOVSX: sign-extends (treats as signed)
MOVSX eax, bl             ; eax = 0xFFFFFFFF = -1 (correct for signed)

; MOVZX: zero-extends (treats as unsigned)
MOVZX eax, bl             ; eax = 0x000000FF = 255 (correct for unsigned)
```

## Practical Use: Signed Array Index

```asm
; Access array with a signed index stored in al (8-bit)
MOVSX rsi, al             ; sign-extend index to 64-bit for addressing
MOV   eax, [rbx + rsi*4] ; load element (correctly handles negative index)
```

## Notes

- Always use MOVSX for **signed** integer promotions.
- Use `MOVSXD` specifically for 32-bit → 64-bit sign extension (separate opcode).
- In 64-bit mode, writing to a 32-bit register zero-extends to 64-bit automatically, so `MOVSX eax, bl` also clears the upper 32 bits of `rax`.

## See Also

- [`MOVZX`](./MOVZX.md) — Move with zero-extension (for unsigned)
- [`MOV`](./MOV.md) — Move (same-size)
- [`CBW` / `CWDE` / `CDQE`] — Sign-extend AL/AX/EAX in-place

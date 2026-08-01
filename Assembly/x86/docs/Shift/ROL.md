# ROL — Rotate Left

## Syntax

```asm
ROL destination, count
```

## Description

Rotates all bits left by `count` positions. Bits that shift off the **left** (MSB side) wrap around and re-enter from the **right** (LSB side). Unlike SHL, no bits are lost.

## Operation (32-bit example, count=1)

```
Before: [b31][b30]...[b1][b0]
After:  [b30][b29]...[b0][b31]    CF = b31 (old MSB)
```

## Flags Affected

| Flag | Effect |
|------|--------|
| CF   | Copy of the bit last rotated from MSB to LSB |
| OF   | Set if count=1 and MSB changed (XOR of two top bits before shift) |
| Others | Unchanged |

## Examples

```asm
; Rotate left by 1
MOV  eax, 0x80000001      ; 10000000 00000000 00000000 00000001
ROL  eax, 1               ; eax = 0x00000003 (bits rotated, CF=1)

; Rotate left by 8 (swap bytes in 32-bit ABCD -> BCDA)
ROL  eax, 8
ROL  eax, 8               ; twice: ABCD -> CDAB

; Byte rotation
ROL  al, 1                ; rotate low byte left

; Variable count
MOV  cl, 4
ROL  eax, cl              ; rotate left by 4 (swap nibbles of low byte if byte)

; Use CF after ROL to test if high bit was set
ROL  eax, 1
JC   high_bit_was_set     ; CF holds the old MSB

; Hash mixing (bit diffusion)
ROL  rax, 17              ; common rotation constant in hash functions
XOR  rax, rbx
ROL  rax, 31
```

## ROL vs SHL

```asm
; SHL: bits lost at MSB, zeros fill LSB
MOV eax, 0x80000001
SHL eax, 1                ; eax = 0x00000002, CF=1 (1 lost from MSB)

; ROL: no bits lost — MSB wraps to LSB
MOV eax, 0x80000001
ROL eax, 1                ; eax = 0x00000003, CF=1 (MSB moved to bit 0)
```

## Notes

- ROL is commonly used in cryptography (e.g., SHA-1 uses ROL 30), hash functions, and CRC computations.
- Count is masked to 5 bits (31 max) for 32-bit, 6 bits for 64-bit.
- Rotating by 32 (or operand-size bits) is a no-op.

## See Also

- [`ROR`](./ROR.md) — Rotate right
- [`RCL`](./RCL.md) — Rotate left through carry (involves CF)
- [`SHL`](./SHL.md) — Shift left (bits lost)

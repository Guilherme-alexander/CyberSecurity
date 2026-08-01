# DEC — Decrement

## Syntax

```asm
DEC destination
```

## Description

Subtracts 1 from `destination`. Equivalent to `SUB destination, 1` **except** that DEC does **not** affect the Carry Flag (CF).

## Flags Affected

| Flag | Effect |
|------|--------|
| CF   | **Not affected** |
| OF   | Set if signed overflow (e.g., INT_MIN - 1) |
| ZF   | Set if result = 0 |
| SF   | Set to sign bit of result |
| PF   | Updated |
| AF   | Updated |

## Examples

```asm
; Decrement register
DEC eax                   ; eax = eax - 1
DEC rcx                   ; rcx = rcx - 1

; Decrement memory
DEC dword [rbp-4]
DEC byte  [rdi]

; Classic countdown loop
MOV ecx, 10
.loop:
    ; ... body ...
    DEC ecx
    JNZ .loop             ; ZF=0 means ecx != 0, keep looping
    ; (JNZ fires when ecx > 0)

; Iterate backwards through array
MOV rsi, array_end        ; point past last element
.back_loop:
    DEC rsi               ; rsi = rsi - 1
    MOV al, [rsi]
    ; process al ...
    CMP rsi, array_start
    JA  .back_loop
```

## Signed Underflow Example

```asm
MOV eax, 0x80000000       ; INT32_MIN = -2,147,483,648
DEC eax                   ; eax = 0x7FFFFFFF = INT32_MAX
; OF = 1 (signed overflow), SF = 0, ZF = 0, CF = unaffected
```

## Notes

- DEC is often paired with `JNZ` for efficient counted loops since DEC sets ZF when the value reaches 0.
- Since CF is unaffected, DEC is safe to use as an outer loop counter in multi-precision inner loops that depend on CF.
- `DEC reg` in 64-bit mode uses a 2-byte encoding (the 1-byte short form was repurposed as REX prefix).

## See Also

- [`INC`](./INC.md) — Increment by 1
- [`SUB`](./SUB.md) — Subtract (does affect CF)
- [`LOOP`](../Jump/LOOP.md) — Implicit DEC of CX/ECX/RCX + conditional jump

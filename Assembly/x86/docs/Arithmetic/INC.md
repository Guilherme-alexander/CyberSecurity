# INC — Increment

## Syntax

```asm
INC destination
```

## Description

Adds 1 to `destination`. Equivalent to `ADD destination, 1` **except** that INC does **not** affect the Carry Flag (CF). This is important in multi-precision arithmetic where CF propagates borrow/carry between words.

## Flags Affected

| Flag | Effect |
|------|--------|
| CF   | **Not affected** (key difference from ADD) |
| OF   | Set if signed overflow (e.g., INT_MAX + 1) |
| ZF   | Set if result = 0 |
| SF   | Set to sign bit of result |
| PF   | Updated |
| AF   | Updated |

## Examples

```asm
; Increment register
INC eax                   ; eax = eax + 1
INC rsi                   ; rsi = rsi + 1 (advance pointer)

; Increment memory
INC dword [rbp-4]         ; increment local variable
INC byte  [rdi]           ; increment byte at pointer

; Loop counter
XOR ecx, ecx
.loop:
    ; ... body ...
    INC ecx
    CMP ecx, 100
    JL  .loop

; Pointer walk
INC rsi                   ; advance byte pointer by 1
```

## INC vs ADD 1

```asm
; INC: does NOT set/clear CF — use in multi-precision loops
INC eax

; ADD 1: DOES set CF — use when you need CF to reflect carry
ADD eax, 1
```

## Signed Overflow Example

```asm
MOV eax, 0x7FFFFFFF       ; INT32_MAX = 2,147,483,647
INC eax                   ; eax = 0x80000000 = -2,147,483,648 (signed)
; OF = 1, SF = 1, ZF = 0, CF = unaffected
```

## Notes

- In 64-bit mode, `INC r32` (32-bit register) zero-extends the result into the 64-bit register.
- On older x86 (pre-64-bit), `INC reg` was a single-byte opcode; in x86-64 those opcodes were repurposed as REX prefixes, so INC uses a 2-byte encoding.
- Compilers sometimes prefer `ADD reg, 1` to avoid partial-flag stalls on older microarchitectures.

## See Also

- [`DEC`](./DEC.md) — Decrement by 1
- [`ADD`](./ADD.md) — Add (does affect CF)
- [`LOOP`](../Jump/LOOP.md) — Decrement CX/ECX/RCX and jump if not zero

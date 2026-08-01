# JC / JB — Jump if Carry / Jump if Below (Unsigned)

## Syntax

```asm
JC  label    ; Jump if Carry Flag set
JB  label    ; Jump if Below (unsigned less-than) — same opcode
JNC label    ; Jump if No Carry
JAE label    ; Jump if Above or Equal — same as JNC
```

## Description

`JC` and `JB` are aliases for the same opcode. They jump when **CF=1**.

After an unsigned comparison (`CMP eax, ebx`):
- CF=1 means `eax < ebx` (unsigned) → **JB** fires
- CF=0 means `eax >= ebx` (unsigned) → **JAE** fires

After arithmetic:
- CF=1 means an unsigned **carry/overflow** occurred → **JC** fires

## Examples

```asm
; Unsigned comparison
CMP  eax, ebx
JB   unsigned_less        ; jump if eax < ebx (unsigned)
JAE  unsigned_ge          ; jump if eax >= ebx (unsigned)

; Detect carry from ADD (unsigned overflow)
ADD  eax, ebx
JC   overflow_handler     ; CF set = result > 0xFFFFFFFF

; Detect borrow from SUB
SUB  eax, ebx
JC   underflow            ; CF set = eax was < ebx unsigned

; Bounds check (unsigned — handles negative indices as large positives)
CMP  rcx, ARRAY_SIZE
JAE  out_of_bounds        ; index >= size (handles negatives correctly!)
```

## JB vs JL (Unsigned vs Signed)

```asm
; eax = 0xFFFFFFFF = 255 unsigned int8 BUT -1 signed

CMP  al, 0
JB   is_below             ; NOT taken: 0xFF = 255 > 0 (unsigned)
JL   is_less              ; TAKEN:     0xFF = -1 < 0 (signed)
```

## See Also

- [`JNC`](./JNC.md) — No carry / above or equal
- [`JL`](./JL.md) — Signed less-than equivalent
- [`ADD`](../Arithmetic/ADD.md) / [`SUB`](../Arithmetic/SUB.md) — Set CF on overflow/borrow

# JL — Jump if Less (Signed)

## Syntax

```asm
JL label
```

Aliases: `JNGE` (Jump if Not Greater or Equal)

## Description

Jumps to `label` if the **signed** comparison result is "less than" — i.e., when SF ≠ OF after a `CMP`.

## Condition

| Mnemonic | Condition       | Flags   |
|----------|-----------------|---------|
| JL       | Less (signed)   | SF ≠ OF |

## Examples

```asm
; Signed less than
CMP  eax, ebx
JL   less_than            ; jump if eax < ebx (signed)

; Loop: count from 0 to 9
XOR  ecx, ecx
.loop:
    ; ... body ...
    INC  ecx
    CMP  ecx, 10
    JL   .loop            ; continue while ecx < 10 (signed)

; Guard: ensure value >= 0
CMP  eax, 0
JL   negative_error       ; bail if signed negative

; Signed clamp
CMP  eax, MIN_VAL
JL   .clamp_low
CMP  eax, MAX_VAL
JG   .clamp_high
JMP  .in_range
.clamp_low:
    MOV eax, MIN_VAL
    JMP .in_range
.clamp_high:
    MOV eax, MAX_VAL
.in_range:
```

## Signed vs Unsigned

```asm
; -1 in 32-bit = 0xFFFFFFFF

CMP eax, 0                ; eax = 0xFFFFFFFF = -1 signed
JL  is_less               ; TAKEN: -1 < 0 (signed comparison SF≠OF)
JB  is_below              ; TAKEN: 0xFFFFFFFF < 0 is FALSE unsigned...
                          ; Wait: 0xFFFFFFFF > 0 unsigned! JB NOT taken.
```

## See Also

- [`JLE`](./JLE.md) — Jump if Less or Equal (signed)
- [`JG`](./JG.md) — Jump if Greater (signed)
- [`JB`](./JC.md) — Jump if Below (unsigned equivalent)
- [`CMP`](../Compare/CMP.md) — Compare

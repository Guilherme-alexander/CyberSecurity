# CMOV — Conditional Move

## Syntax

```asm
CMOVcc destination, source
```

Where `cc` is a condition code (see table below).

## Description

Moves `source` into `destination` **only if** the specified condition (based on EFLAGS) is true. If the condition is false, the instruction is a no-op — the destination is unchanged. `source` must be a register or memory; `destination` must be a register.

## Condition Codes

| Mnemonic | Condition           | Flags         |
|----------|---------------------|---------------|
| CMOVE    | Equal / Zero        | ZF=1          |
| CMOVNE   | Not Equal / Not Zero| ZF=0          |
| CMOVL    | Less (signed)       | SF≠OF         |
| CMOVLE   | Less or Equal (signed)| ZF=1 or SF≠OF|
| CMOVG    | Greater (signed)    | ZF=0 and SF=OF|
| CMOVGE   | Greater or Equal (signed)| SF=OF    |
| CMOVB    | Below (unsigned)    | CF=1          |
| CMOVBE   | Below or Equal (unsigned)| CF=1 or ZF=1|
| CMOVA    | Above (unsigned)    | CF=0 and ZF=0 |
| CMOVAE   | Above or Equal (unsigned)| CF=0     |
| CMOVS    | Sign (negative)     | SF=1          |
| CMOVNS   | Not Sign            | SF=0          |
| CMOVO    | Overflow            | OF=1          |
| CMOVNO   | No Overflow         | OF=0          |

## Flags Affected

None. CMOV reads but does not modify EFLAGS.

## Examples

```asm
; Branchless absolute value
MOV  edx, eax
NEG  edx                  ; edx = -eax
CMOVL eax, edx            ; if eax was negative (SF set after NEG), use edx
; Result: eax = |original_eax|

; Branchless maximum (signed)
CMP  eax, ebx
CMOVL eax, ebx            ; eax = max(eax, ebx)

; Branchless minimum (signed)
CMP  eax, ebx
CMOVG eax, ebx            ; eax = min(eax, ebx)

; Clamp value to [0, 255]
XOR  edx, edx
CMP  eax, 0
CMOVL eax, edx            ; if eax < 0, eax = 0
MOV  edx, 255
CMP  eax, 255
CMOVG eax, edx            ; if eax > 255, eax = 255

; Select between two computed results
CMP  ecx, 0
CMOVNE eax, ebx           ; if ecx != 0, use ebx instead of eax
```

## Why Use CMOV?

```asm
; Traditional branch (can cause branch misprediction penalty):
CMP  eax, ebx
JGE  .not_less
MOV  eax, ebx
.not_less:

; Branchless with CMOV (no misprediction, often faster in tight loops):
CMP  eax, ebx
CMOVL eax, ebx
```

## Notes

- CMOV was introduced with **Pentium Pro** (P6, 1995) and is present in all modern x86-64 CPUs.
- CMOV eliminates branch misprediction but still has a data dependency — useful when the branch is **hard to predict**.
- If the branch is **easily predicted** (e.g., almost always taken), a regular JMP is often faster.
- The source operand is **always read** regardless of the condition; only the write to destination is conditional.
- There is no 8-bit form — minimum operand size is 16-bit.

## See Also

- [`MOV`](./MOV.md) — Unconditional move
- [`CMP`](../Compare/CMP.md) — Compare (sets flags for CMOV)
- [`SETcc`](../Compare/SETcc.md) — Set byte on condition
- [`JMP`](../Jump/JMP.md) — Conditional jump (alternative)

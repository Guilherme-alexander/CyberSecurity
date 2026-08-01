# SETcc — Set Byte on Condition

## Syntax

```asm
SETcc destination
```

Where `cc` is a condition code. `destination` must be an 8-bit register or byte memory location.

## Description

Sets `destination` to **1** if the condition is true, or **0** if false. Useful for converting flag results to integer values without branching.

## Condition Codes

| Mnemonic | Condition             | Flags          |
|----------|-----------------------|----------------|
| SETE / SETZ  | Equal / Zero      | ZF=1           |
| SETNE / SETNZ| Not Equal / Not Zero| ZF=0         |
| SETL / SETNGE| Less (signed)     | SF≠OF          |
| SETLE / SETNG| Less or Equal (signed)| ZF=1 or SF≠OF|
| SETG / SETNLE| Greater (signed)  | ZF=0 and SF=OF |
| SETGE / SETNL| Greater or Equal (signed)| SF=OF   |
| SETB / SETC  | Below (unsigned)  | CF=1           |
| SETBE        | Below or Equal (unsigned)| CF=1 or ZF=1|
| SETA         | Above (unsigned)  | CF=0 and ZF=0  |
| SETAE / SETNC| Above or Equal    | CF=0           |
| SETS         | Sign (negative)   | SF=1           |
| SETNS        | Not Sign          | SF=0           |
| SETO         | Overflow          | OF=1           |
| SETNO        | No Overflow       | OF=0           |

## Flags Affected

None. SETcc reads but does not modify EFLAGS.

## Examples

```asm
; Branchless bool: result = (eax == ebx)
CMP  eax, ebx
SETE al                   ; al = 1 if equal, 0 otherwise

; Extend to 32-bit integer (0 or 1)
CMP  eax, ebx
SETE al
MOVZX eax, al             ; eax = 0 or 1

; Branchless max (unsigned)
CMP  eax, ebx
SETA cl                   ; cl = 1 if eax > ebx (unsigned)

; Count matching elements (branchless)
XOR  ecx, ecx
.loop:
    CMP  byte [rsi + rcx], TARGET
    SETE al
    MOVZX eax, al
    ADD  edx, eax         ; accumulate count
    INC  ecx
    CMP  ecx, LENGTH
    JL   .loop

; Saturating flag to 0/1
TEST eax, eax
SETNE al                  ; al = (eax != 0)  i.e., "is eax nonzero?"
MOVZX eax, al

; Compare and store result in struct field
CMP  eax, THRESHOLD
SETGE [result + offset]   ; store 1 if >= threshold, 0 otherwise
```

## Branchless vs Branch

```asm
; Branching version (may mispredict):
CMP  eax, 0
JL   .negative
MOV  eax, 0
JMP  .done
.negative:
    MOV eax, -1
.done:

; Branchless version using SETcc:
CMP  eax, 0
SETL al                   ; al = 1 if eax < 0
MOVZX eax, al             ; eax = 0 or 1
NEG  eax                  ; eax = 0 or -1
```

## Notes

- SETcc always produces 0 or 1 — never another value.
- The destination is **always 8-bit**; use `MOVZX` to widen to 16/32/64 bits.
- Multiple SETcc/CMOV instructions are often combined by compilers for complex boolean expressions.
- Introduced with 80386.

## See Also

- [`CMP`](./CMP.md) — Compare (primary flag-setter for SETcc)
- [`CMOV`](../DataTransfer/CMOV.md) — Conditional move
- [`TEST`](../Logic/TEST.md) — Non-destructive AND for flag-setting

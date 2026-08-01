# CMPS — Compare Strings

## Syntax

```asm
CMPSB           ; compare [RSI] with [RDI], advance both by 1
CMPSW           ; compare [RSI] with [RDI], advance both by 2
CMPSD           ; compare [RSI] with [RDI], advance both by 4
CMPSQ           ; compare [RSI] with [RDI], advance both by 8

REPE  CMPSB     ; repeat while equal (memcmp until mismatch)
REPNE CMPSB     ; repeat while not equal (find first match)
```

## Description

Compares the value at `[RSI]` with `[RDI]`, sets flags like CMP, then advances both RSI and RDI. With `REPE`, scans until a **mismatch** is found — implementing **memcmp** or **strcmp**.

## Flags Affected

Same as CMP. RSI, RDI, RCX modified.

## Examples

```asm
; memcmp: compare two buffers
CLD
LEA  rsi, [buf1]
LEA  rdi, [buf2]
MOV  rcx, LENGTH
REPE CMPSB                ; scan while bytes are equal
JE   buffers_equal        ; ZF=1 after loop: all bytes matched
; if not equal: rsi-1 and rdi-1 point to the differing bytes
; use MOVZX + SUB to get signed difference like memcmp return value

; strcmp: compare null-terminated strings
CLD
LEA  rsi, [str1]
LEA  rdi, [str2]
MOV  rcx, MAX_LEN
REPE CMPSB
JE   strings_equal
JA   str1_greater         ; unsigned: byte in str1 > byte in str2
JB   str2_greater

; Find first common byte in two buffers (REPNE)
CLD
LEA  rsi, [buf1]
LEA  rdi, [buf2]
MOV  rcx, LEN
REPNE CMPSB               ; scan until bytes match
JNZ  no_common_byte
; match found: bytes were equal at rsi-1 and rdi-1
```

## After REPE CMPSB

```asm
; ZF=1: all RCX bytes matched (buffers equal)
; ZF=0: mismatch found at [RSI-1] vs [RDI-1]
;       use JA/JB for unsigned byte comparison
;       use JG/JL for signed byte comparison
```

## Notes

- RSI = "string 1" (source), RDI = "string 2" (destination register by convention).
- After the REP terminates, RSI and RDI point **one past** the last compared byte.
- For signed `strcmp`-style comparison, note that ASCII comparison of bytes is unsigned.
- CMPSB is less commonly used than SCASB in modern code; compilers often unroll with MOVZX + CMP.

## See Also

- [`SCAS`](./SCAS.md) — Scan (compare with accumulator, not memory-to-memory)
- [`MOVSB`](./MOVSB.md) — Copy string
- [`REPE`] / [`REPNE`] — Repeat prefix instructions

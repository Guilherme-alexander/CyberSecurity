# SCAS — Scan String

## Syntax

```asm
SCASB           ; compare AL  with [RDI], advance RDI by 1
SCASW           ; compare AX  with [RDI], advance RDI by 2
SCASD           ; compare EAX with [RDI], advance RDI by 4
SCASQ           ; compare RAX with [RDI], advance RDI by 8

REPNE SCASB     ; repeat until match or RCX=0
REPE  SCASB     ; repeat while equal or RCX=0
```

## Description

Compares AL/AX/EAX/RAX with the value at `[RDI]`, sets flags (like CMP), and advances RDI. Combined with `REPNE` (repeat while not equal), implements **memchr** / **strlen**.

## Flags Affected

Same as CMP: ZF, SF, CF, OF, PF, AF updated. RDI and RCX modified.

## Examples

```asm
; strlen: find null byte in string
CLD
LEA  rdi, [string]
XOR  eax, eax             ; al = 0 (null byte we're searching for)
MOV  rcx, 0xFFFFFFFF      ; max length
REPNE SCASB               ; scan until [rdi] == al (null) or rcx=0
NOT  rcx                  ; rcx = ~(remaining count)
DEC  rcx                  ; subtract 1 for the null byte itself
; rcx = string length

; memchr: find first occurrence of byte
CLD
LEA  rdi, [buffer]
MOV  al, TARGET_BYTE
MOV  rcx, BUFFER_LEN
REPNE SCASB               ; scan until match or end
JNZ  not_found            ; ZF=0: no match
LEA  rax, [rdi-1]         ; rdi was advanced past the match

; Count matching bytes (REPE — scan while equal)
CLD
LEA  rdi, [buffer]
MOV  al, ' '              ; count leading spaces
MOV  rcx, BUF_LEN
REPE SCASB                ; scan while [rdi] == al
; rcx holds (BUF_LEN - leading_space_count - 1)

; Verify fixed-length field is all zeros
CLD
LEA  rdi, [field]
XOR  eax, eax
MOV  rcx, FIELD_LEN
REPE SCASB                ; scan while zero
JNZ  not_all_zeros        ; stopped early: non-zero byte found
```

## After REPNE SCASB

```asm
REPNE SCASB
; After termination:
; ZF=1: match found at [RDI-1]
; ZF=0: RCX reached 0 (not found)
; RDI points ONE PAST the matching (or last scanned) byte
```

## Notes

- RDI is the **destination** register for SCAS (confusingly named — "destination" of the scan).
- AL is the **search value**.
- `REPNE SCASB` with AL=0 is the classic strlen implementation.
- After REPNE SCASB finds a match, RDI points **past** the match: the match is at `[RDI-1]`.

## See Also

- [`CMPS`](./CMPS.md) — Compare two strings
- [`LODS`](./LODS.md) — Load from string
- [`STOS`](./STOS.md) — Store to string

# STOS — Store String (memset)

## Syntax

```asm
STOSB           ; store AL  to [RDI], advance RDI by 1
STOSW           ; store AX  to [RDI], advance RDI by 2
STOSD           ; store EAX to [RDI], advance RDI by 4
STOSQ           ; store RAX to [RDI], advance RDI by 8

REP STOSB       ; repeat ECX/RCX times
```

## Description

Stores the value in AL/AX/EAX/RAX to the memory address in RDI, then advances RDI by the operand size. With `REP`, implements a **memset** operation.

## Setup Required

| Register | Role |
|----------|------|
| AL/AX/EAX/RAX | Value to store |
| RDI | Destination pointer |
| RCX | Repeat count (REP) |
| DF | Direction flag (CLD for forward) |

## Flags Affected

None (RDI and RCX modified).

## Examples

```asm
; memset: fill 256 bytes with 0
CLD
LEA  rdi, [buffer]
XOR  eax, eax             ; al = 0
MOV  rcx, 256
REP  STOSB

; Fill with a specific byte value
CLD
LEA  rdi, [buffer]
MOV  al, 0xFF
MOV  rcx, 64
REP  STOSB                ; set 64 bytes to 0xFF

; Zero a 32-bit integer array (STOSD — 4 bytes per iteration)
CLD
LEA  rdi, [int_array]
XOR  eax, eax
MOV  rcx, ARRAY_SIZE      ; number of elements
REP  STOSD                ; zeros ARRAY_SIZE * 4 bytes

; Zero a struct
CLD
LEA  rdi, [my_struct]
XOR  eax, eax
MOV  rcx, sizeof_struct / 8  ; in QWORDs
REP  STOSQ

; Fill a string with spaces
CLD
LEA  rdi, [str_buf]
MOV  al, ' '
MOV  rcx, BUF_LEN
REP  STOSB
```

## REP STOSD vs REP STOSB

```asm
; STOSD fills 4 bytes at a time — 4x faster for large zero-fills (aligned)
; STOSB fills 1 byte at a time — use for arbitrary sizes or unaligned data

; Optimal pattern for arbitrary size:
MOV  rcx, N / 8
REP  STOSQ               ; fill 8 bytes at a time
MOV  rcx, N % 8
REP  STOSB               ; handle remainder
```

## Notes

- `REP STOSB` is the assembly equivalent of `memset(ptr, byte, count)`.
- Always CLD before REP STOS in normal code.
- Like MOVSB, modern Intel CPUs have fast-string hardware for REP STOS.

## See Also

- [`MOVSB`](./MOVSB.md) — Copy memory (memcpy)
- [`LODSB`](./LODS.md) — Load from string
- [`SCASB`](./SCAS.md) — Scan string (find value)
- [`CLD`](../Flags/CLD.md) — Clear direction flag

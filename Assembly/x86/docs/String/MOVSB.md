# MOVSB — Move String Byte

## Syntax

```asm
MOVSB           ; move 1 byte: [RSI] -> [RDI], advance both
REP MOVSB       ; repeat ECX/RCX times
```

## Description

Copies a **single byte** from `[RSI]` to `[RDI]`, then adjusts both pointers by 1 (direction: DF=0 increments, DF=1 decrements). When preceded by `REP`, repeats ECX/RCX times — implementing a fast byte-level `memcpy`.

## Setup Required

| Register | Role |
|----------|------|
| RSI | Source pointer |
| RDI | Destination pointer |
| RCX | Repeat count (for REP prefix) |
| DF (Direction Flag) | 0=forward (CLD), 1=backward (STD) |

## Flags Affected

DF is read (not modified). RSI and RDI are modified. EFLAGS otherwise unchanged.

## Examples

```asm
; Copy a single byte
MOV  rsi, src
MOV  rdi, dst
MOVSB                     ; copy 1 byte [src] -> [dst]
; rsi = src+1, rdi = dst+1

; memcpy: copy N bytes forward
CLD                       ; DF=0: increment addresses
LEA  rsi, [src]
LEA  rdi, [dst]
MOV  rcx, LENGTH
REP  MOVSB                ; copy rcx bytes

; Copy a C string (strcpy — careful: no bounds check)
CLD
LEA  rsi, [source_str]
LEA  rdi, [dest_buf]
.copy_loop:
    LODSB                 ; al = [rsi++]
    STOSB                 ; [rdi++] = al
    TEST al, al
    JNZ  .copy_loop       ; stop after copying the null terminator

; Backward copy (for overlapping regions where dst > src)
STD                       ; DF=1: decrement
LEA  rsi, [src + LENGTH - 1]   ; start from last byte
LEA  rdi, [dst + LENGTH - 1]
MOV  rcx, LENGTH
REP  MOVSB
CLD                       ; restore DF to 0 (good practice)
```

## Performance Tips

```asm
; REP MOVSB is highly optimized on modern CPUs (ERMSB — Enhanced REP MOVSB)
; For large copies it's often as fast as SSE/AVX memcpy

; For small known sizes, use MOVSQ (8 bytes at once) + MOVSB remainder:
MOV  rcx, LENGTH / 8
REP  MOVSQ               ; copy in 8-byte chunks
MOV  rcx, LENGTH % 8
REP  MOVSB               ; copy remaining bytes
```

## Notes

- Always set **CLD** (clear direction flag) before REP MOVSB in most contexts; many calling conventions leave DF unspecified.
- On Intel CPUs with ERMSB feature, `REP MOVSB` is a near-optimal memcpy implementation.
- For overlapping copies where `dst > src`, copy backward (STD) to avoid overwriting source data.

## See Also

- [`MOVSW`](./MOVSW.md) — Move word (2 bytes)
- [`MOVSD`](./MOVSD.md) — Move doubleword (4 bytes)
- [`STOSB`](./STOS.md) — Store byte (memset-like)
- [`LODSB`](./LODS.md) — Load byte from string
- [`CLD`](../Flags/CLD.md) / [`STD`](../Flags/STD.md) — Direction flag

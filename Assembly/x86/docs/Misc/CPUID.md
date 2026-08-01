# CPUID — CPU Identification

## Syntax

```asm
CPUID
```

## Description

Returns processor identification and feature information in EAX, EBX, ECX, and EDX. The **leaf** (query type) is passed in EAX before the instruction; some leaves also use ECX as a sub-leaf.

## Registers Used

| Register | Role |
|----------|------|
| EAX (in)  | Leaf number (query) |
| ECX (in)  | Sub-leaf (for some leaves) |
| EAX, EBX, ECX, EDX (out) | Result fields |

## Flags Affected

None (EAX, EBX, ECX, EDX are overwritten).

## Common Leaves

| EAX in | Information returned |
|--------|---------------------|
| 0x0    | Max basic leaf + vendor string |
| 0x1    | Family/model/stepping + feature flags |
| 0x7    | Extended features (AVX2, BMI, etc.) |
| 0x80000000 | Max extended leaf |
| 0x80000001 | Extended features (LAHF, LZCNT…) |
| 0x80000002–4 | Processor brand string |

## Examples

```asm
; Get vendor string (EBX:EDX:ECX form 12 ASCII bytes)
XOR  eax, eax             ; leaf 0
CPUID
; EBX = "Genu", EDX = "ineI", ECX = "ntel" for Intel
; EBX = "Auth", EDX = "enti", ECX = "cAMD" for AMD

; Check for SSE2 support (leaf 1, EDX bit 26)
MOV  eax, 1
CPUID
TEST edx, (1 << 26)       ; SSE2 feature bit
JZ   no_sse2

; Check for AVX2 support (leaf 7, sub-leaf 0, EBX bit 5)
MOV  eax, 7
XOR  ecx, ecx             ; sub-leaf 0
CPUID
TEST ebx, (1 << 5)        ; AVX2 bit
JZ   no_avx2

; Check for POPCNT (leaf 1, ECX bit 23)
MOV  eax, 1
CPUID
TEST ecx, (1 << 23)
JNZ  has_popcnt

; Read processor brand string (3 leaves, 48 chars total)
section .bss
    brand_str resb 49     ; 48 bytes + null terminator

section .text
    LEA  rdi, [brand_str]
    MOV  eax, 0x80000002
    CPUID
    MOV  [rdi],    eax
    MOV  [rdi+4],  ebx
    MOV  [rdi+8],  ecx
    MOV  [rdi+12], edx
    MOV  eax, 0x80000003
    CPUID
    MOV  [rdi+16], eax
    ; ... (continue for 0x80000004)
```

## Feature Bits (Leaf 1)

| Register | Bit | Feature |
|----------|-----|---------|
| EDX | 25  | SSE    |
| EDX | 26  | SSE2   |
| ECX | 0   | SSE3   |
| ECX | 9   | SSSE3  |
| ECX | 19  | SSE4.1 |
| ECX | 20  | SSE4.2 |
| ECX | 23  | POPCNT |
| ECX | 28  | AVX    |

## Notes

- CPUID was added with the Pentium; check bit 21 of EFLAGS (ID flag) to confirm support (all modern CPUs have it).
- The `CPUID` instruction serializes the instruction stream — also useful as a fence.
- Libraries like glibc and compiler runtimes use CPUID at startup to select optimized code paths.

## See Also

- [`RDTSC`](./RDTSC.md) — Read Time-Stamp Counter
- [`NOP`](./NOP.md) — Multi-byte NOPs often depend on CPU feature detection

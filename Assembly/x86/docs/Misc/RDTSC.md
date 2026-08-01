# RDTSC — Read Time-Stamp Counter

## Syntax

```asm
RDTSC
```

## Description

Reads the processor's **64-bit Time-Stamp Counter** (TSC) into EDX:EAX (high 32 bits in EDX, low 32 bits in EAX). The TSC increments at a fixed rate (tied to the processor's rated frequency) and is the fastest way to measure elapsed cycles in user space.

## Flags Affected

None. EDX and EAX are overwritten.

## Examples

```asm
; Basic timing: measure instruction latency
RDTSC
MOV  esi, eax             ; save low 32 bits of start time
MOV  edi, edx             ; save high 32 bits

; ... code to measure ...
IMUL eax, ebx

RDTSC                     ; read end time
; Compute elapsed (assuming no overflow in 32 bits):
SUB  eax, esi             ; elapsed low
; Full 64-bit elapsed in RDX:RAX before the second RDTSC

; 64-bit elapsed cycles
RDTSC
SHL  rdx, 32
OR   rax, rdx             ; rax = full 64-bit TSC (start)
MOV  r8, rax

; ... measured code ...

RDTSC
SHL  rdx, 32
OR   rax, rdx             ; rax = TSC (end)
SUB  rax, r8              ; rax = elapsed cycles

; Use RDTSCP for more accurate serialized reading
RDTSCP                    ; also returns core ID in ECX
SHL  rdx, 32
OR   rax, rdx
```

## Preventing Reordering

```asm
; Without fencing, CPU/compiler may reorder RDTSC:
CPUID                     ; serializing instruction (no reorder before this)
RDTSC
MOV  r8, rax
; ... measured code ...
RDTSCP                    ; RDTSCP waits for prior instructions to complete
```

## Practical Microbenchmark Pattern

```asm
; Warmup + measure (repeat N times, take minimum)
MOV  r15, ITERATIONS
.bench_loop:
    CPUID                 ; serialize
    RDTSC
    MOV  r12, rax         ; start

    ; --- code under test ---
    IMUL eax, ebx
    ; ----------------------

    RDTSCP                ; end (serialized)
    SUB  eax, r12d        ; elapsed (low 32 bits, sufficient for short sequences)

    CMP  eax, r13d        ; compare with minimum
    JA   .not_min
    MOV  r13d, eax        ; update minimum
.not_min:
    DEC  r15
    JNZ  .bench_loop
; r13 = minimum cycle count
```

## Notes

- TSC frequency is **constant** on modern CPUs (constant TSC feature — check CPUID leaf 0x80000007 EDX bit 8).
- TSC is per-core; on multi-core systems, OS may migrate your thread — use RDTSCP (also returns `IA32_TSC_AUX` in ECX, which encodes core/socket ID).
- For wall-clock time, prefer OS APIs (`clock_gettime`); RDTSC is for **cycle counting** in microbenchmarks.
- Virtualized environments may intercept RDTSC and return fake values.

## See Also

- [`CPUID`](./CPUID.md) — CPU features (use to verify invariant TSC)
- [`RDTSCP`] — RDTSC + serialization + core ID
- [`NOP`](./NOP.md) — Used in timing loops

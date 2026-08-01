# CLI — Clear Interrupt Flag

## Syntax

```asm
CLI
```

## Description

Clears the Interrupt Enable Flag (IF) to 0, **disabling maskable hardware interrupts** on the current CPU. The processor will not respond to external interrupt requests (IRQs) until IF is restored with STI.

## Flags Affected

**IF = 0**. No other flags modified.

## Privilege Required

**Ring 0 (kernel mode) only.** Executing CLI in user mode causes a #GP (General Protection Fault) on standard x86 systems. (Exception: virtual-mode environments like VMX or IOPL=3 may allow it.)

## Examples

```asm
; Kernel: enter critical section without interruption
CLI                       ; disable interrupts
; ... modify shared data structures ...
; ... critical section (keep SHORT — interrupts are disabled!) ...
STI                       ; re-enable interrupts

; Save and restore interrupt state (safer pattern)
PUSHF                     ; save EFLAGS (including IF)
CLI                       ; disable interrupts
; ... critical section ...
POPF                      ; restore original interrupt state (re-enables if was enabled)

; Spinlock implementation (kernel)
CLI
MOV  eax, 1
XCHG eax, [lock]
STI
TEST eax, eax
JNZ  retry                ; lock was held, retry

; Common kernel pattern: interrupt-safe counter update
CLI
INC  dword [shared_counter]
STI
```

## Critical Sections Should Be Short

```asm
; WRONG: long critical section — degrades system responsiveness
CLI
; ... 10,000 instructions ...
STI

; RIGHT: minimal critical section
CLI
MOV  eax, [shared_var]    ; read
ADD  eax, 1               ; compute
MOV  [shared_var], eax    ; write
STI
; Or better: use LOCK prefix / atomic operations instead
```

## Notes

- CLI only disables **maskable** interrupts (NMI — Non-Maskable Interrupt — is unaffected).
- Modern kernels minimize CLI/STI use; prefer `LOCK`-prefixed atomic operations or per-CPU data.
- On multi-core systems, CLI only disables interrupts on the **current CPU core** — other cores still run.

## See Also

- [`STI`](./STI.md) — Set Interrupt Flag (re-enable interrupts)
- [`PUSHF`] / [`POPF`] — Save/restore entire flags register
- [`INT`](../Misc/INT.md) — Software interrupt

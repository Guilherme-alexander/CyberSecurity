# STI — Set Interrupt Flag

## Syntax

```asm
STI
```

## Description

Sets the Interrupt Enable Flag (IF) to 1, **re-enabling maskable hardware interrupts** on the current CPU. After STI, the processor will handle pending IRQs before executing the next instruction (with a one-instruction delay on some architectures).

## Flags Affected

**IF = 1**. No other flags modified.

## Privilege Required

**Ring 0 (kernel mode) only** under normal conditions.

## Examples

```asm
; Re-enable interrupts after a critical section
CLI
; ... critical section ...
STI

; Interrupt handler epilogue
; (after saving state, processing, and restoring state)
IRETQ                     ; IRET automatically restores IF from saved EFLAGS

; Halt the CPU until next interrupt (idle loop)
STI
HLT                       ; CPU sleeps; wakes on next interrupt
; execution continues here after the interrupt handler returns

; Safe interrupt-state save/restore with PUSHF/POPF
PUSHF
CLI
; ... critical section ...
POPF                      ; restores IF to its value before CLI
```

## One-Instruction Shadow

```asm
; On x86, STI enables interrupts AFTER the next instruction completes:
STI
HLT                       ; this executes before an interrupt can fire
; This guarantees the CPU reaches HLT (and sleeps) before any interrupt wakes it.
```

## Notes

- STI is the counterpart to CLI; always pair them.
- The one-instruction delay after STI prevents a race condition in `STI; HLT`.
- On multi-core systems, STI only affects the **current CPU core**.
- User-mode code should never need STI; use kernel APIs / atomic operations instead.

## See Also

- [`CLI`](./CLI.md) — Clear Interrupt Flag
- [`HLT`](../Misc/HLT.md) — Halt until interrupt
- [`INT`](../Misc/INT.md) — Software interrupt

# HLT — Halt Processor

## Syntax

```asm
HLT
```

## Description

Stops instruction execution and puts the CPU into a **halted state** until one of the following occurs:
- A maskable external interrupt (if IF=1)
- A Non-Maskable Interrupt (NMI)
- A reset

After handling the interrupt, execution resumes at the instruction following HLT.

## Flags Affected

None.

## Privilege Required

**Ring 0 (kernel mode) only.** HLT in user mode causes #GP (General Protection Fault).

## Examples

```asm
; Kernel idle loop — CPU sleeps until next interrupt
idle_loop:
    STI                   ; ensure interrupts are enabled
    HLT                   ; sleep until interrupt fires
    JMP idle_loop         ; after interrupt handler returns, sleep again

; The STI + HLT pair is deliberate:
; STI enables interrupts; HLT occurs before any pending interrupt fires
; (one-instruction shadow of STI guarantees this)

; Bootloader: halt after fatal error
panic:
    CLI                   ; disable interrupts (we're done)
    HLT                   ; halt forever
    JMP panic             ; in case of NMI, halt again

; OS shutdown
shutdown:
    CLI
    ; ... save state, flush buffers ...
    HLT

; ACPI power-off (real kernel code calls ACPI, but at lowest level):
    OUT  0x604, ax        ; QEMU/Bochs power off port (not real ACPI)
    HLT                   ; fallback if power-off doesn't work
```

## Power States

```asm
; HLT puts CPU in C1 (Halt) power state.
; Modern kernels use MWAIT for deeper sleep states (C2/C3):
;   MONITOR + MWAIT can sleep until a specific memory location changes.

; Simple C1 idle (Linux-style):
sti                       ; enable interrupts
hlt                       ; wait for interrupt
```

## Notes

- HLT is the basis of every OS idle loop — running `while(1);` wastes CPU power; `STI; HLT` is energy-efficient.
- On multi-core systems, HLT only halts the **current core**.
- HLT does not save any registers — it just pauses the instruction pointer.
- In virtual machines, HLT is intercepted by the hypervisor to yield the host thread.

## See Also

- [`STI`](../Flags/STI.md) — Enable interrupts (required before HLT in idle loops)
- [`CLI`](../Flags/CLI.md) — Disable interrupts
- [`INT`](./INT.md) — Software interrupt
- [`NOP`](./NOP.md) — No operation (CPU still runs, unlike HLT)

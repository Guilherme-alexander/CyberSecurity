# INT — Software Interrupt

## Syntax

```asm
INT  imm8       ; trigger interrupt vector N
INT3            ; breakpoint (0xCC — 1-byte encoding of INT 3)
INTO            ; interrupt on overflow (INT 4 if OF=1) — 32-bit only
```

## Description

Triggers a software interrupt, invoking the handler at the specified interrupt vector. The CPU pushes EFLAGS, CS, and EIP (or their 64-bit equivalents) onto the stack and jumps to the handler. Used for system calls (legacy Linux, DOS), debugger breakpoints, and BIOS services.

## Flags Affected

TF and IF are cleared by the interrupt mechanism. Other flags saved to stack.

## Examples

```asm
; --- Linux 32-bit system call (legacy) ---
MOV  eax, 1               ; syscall number: sys_exit
MOV  ebx, 0               ; exit code 0
INT  0x80                 ; invoke kernel

; --- BIOS video service (real mode / bootloader) ---
MOV  ah, 0x0E             ; BIOS teletype output
MOV  al, 'H'              ; character
INT  0x10                 ; BIOS video interrupt

; --- BIOS disk service (real mode) ---
MOV  ah, 0x02             ; read sectors
MOV  al, 1                ; sector count
MOV  ch, 0                ; cylinder
MOV  cl, 2                ; sector
MOV  dh, 0                ; head
MOV  dl, 0x80             ; drive (0x80 = first HDD)
INT  0x13

; --- Debugger breakpoint ---
INT3                      ; 0xCC: trap to debugger
; Code after INT3 executes when debugger continues

; --- DOS system call (16-bit, historical) ---
MOV  ah, 0x09             ; DOS print string
LEA  dx, [message]        ; pointer to '$'-terminated string
INT  0x21
```

## INT vs SYSCALL

| Method | Mode | Usage |
|--------|------|-------|
| `INT 0x80` | 32-bit Linux | Legacy system calls |
| `SYSCALL` | 64-bit Linux/macOS | Modern system calls |
| `INT 0x21` | 16-bit DOS | DOS API |
| `INT 0x10/0x13` | Real mode | BIOS services |
| `INT3` | Any | Debugger breakpoint |

## INT3 — Breakpoint Instruction

```asm
; INT3 (0xCC) is a special 1-byte form of INT 3
; Used by debuggers to set breakpoints:
; 1. Debugger saves original byte at target address
; 2. Writes 0xCC at that address
; 3. CPU traps to debugger when executed
; 4. Debugger restores original byte, shows you the state

; In your own code, INT3 invokes the debugger immediately:
INT3                      ; execution stops here in a debugger
MOV  eax, magic_value     ; inspect registers/memory at this point
```

## Notes

- In 64-bit user-mode code, use `SYSCALL` instead of `INT 0x80` — it's faster (no privilege-level change overhead).
- `INT3` is 1 byte (0xCC); `INT 3` is 2 bytes (0xCD 0x03) — debuggers always patch with 0xCC.
- Hardware interrupts use the same IDT (Interrupt Descriptor Table) as software INT.

## See Also

- [`SYSCALL`](./SYSCALL.md) — Fast 64-bit system call
- [`HLT`](./HLT.md) — Halt until interrupt
- [`STI`](../Flags/STI.md) / [`CLI`](../Flags/CLI.md) — Enable/disable interrupts

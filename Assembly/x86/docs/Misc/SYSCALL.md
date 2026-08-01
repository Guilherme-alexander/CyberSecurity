# SYSCALL — Fast System Call (64-bit)

## Syntax

```asm
SYSCALL
```

## Description

Transfers control to the OS kernel for a system call, using a fast path that avoids the overhead of `INT 0x80`. The kernel uses registers to receive the call number and arguments, and returns results in RAX.

## Register Convention (Linux x86-64)

| Register | Role |
|----------|------|
| RAX | Syscall number (input) / Return value (output) |
| RDI | Argument 1 |
| RSI | Argument 2 |
| RDX | Argument 3 |
| R10 | Argument 4 (note: R10, not RCX!) |
| R8  | Argument 5 |
| R9  | Argument 6 |
| RCX | Destroyed (saved RIP by CPU) |
| R11 | Destroyed (saved RFLAGS by CPU) |

## Flags Affected

RCX and R11 are clobbered. RAX is overwritten with the return value.

## Examples

```asm
; sys_write(1, message, length) — write to stdout
section .data
    msg db "Hello, World!", 10    ; message + newline
    msg_len equ $ - msg

section .text
global _start
_start:
    MOV  rax, 1           ; syscall: sys_write
    MOV  rdi, 1           ; fd: stdout (1)
    LEA  rsi, [msg]       ; buffer pointer
    MOV  rdx, msg_len     ; byte count
    SYSCALL               ; write(1, msg, msg_len)

; sys_exit(0) — exit program
    MOV  rax, 60          ; syscall: sys_exit
    XOR  rdi, rdi         ; exit code: 0
    SYSCALL

; sys_read(0, buf, 256) — read from stdin
    MOV  rax, 0           ; syscall: sys_read
    XOR  rdi, rdi         ; fd: stdin (0)
    LEA  rsi, [buf]       ; buffer
    MOV  rdx, 256         ; max bytes
    SYSCALL               ; returns bytes read in rax

; sys_open("/tmp/file", O_RDONLY, 0)
    MOV  rax, 2           ; syscall: sys_open
    LEA  rdi, [filename]  ; pathname
    XOR  rsi, rsi         ; flags: O_RDONLY = 0
    XOR  rdx, rdx         ; mode: 0
    SYSCALL               ; returns fd in rax (negative = error)

; sys_brk — extend heap
    MOV  rax, 12          ; syscall: sys_brk
    MOV  rdi, new_brk     ; new program break
    SYSCALL               ; returns new break or -1
```

## Common Linux Syscall Numbers (x86-64)

| Number | Name | Description |
|--------|------|-------------|
| 0  | read   | Read from file descriptor |
| 1  | write  | Write to file descriptor |
| 2  | open   | Open file |
| 3  | close  | Close file descriptor |
| 9  | mmap   | Map memory |
| 11 | munmap | Unmap memory |
| 12 | brk    | Adjust heap break |
| 39 | getpid | Get process ID |
| 57 | fork   | Fork process |
| 59 | execve | Execute program |
| 60 | exit   | Exit process |
| 231| exit_group | Exit all threads |

Full list: `/usr/include/asm/unistd_64.h` or `man 2 syscall`.

## Error Handling

```asm
SYSCALL
TEST rax, rax
JS   error_handler        ; negative return = error code (-errno)
; success: rax >= 0
```

## Notes

- SYSCALL is **only available in 64-bit mode**; use `INT 0x80` for 32-bit Linux.
- Argument 4 uses **R10**, not RCX (RCX is destroyed by SYSCALL itself to save RIP).
- On macOS (Darwin), syscall numbers differ and the convention uses `0x2000000 | number` in RAX.
- SYSENTER/SYSEXIT is the 32-bit fast syscall equivalent.

## See Also

- [`INT`](./INT.md) — Legacy software interrupt (INT 0x80 for 32-bit Linux)
- [`SYSENTER`] — Fast 32-bit system call
- [`HLT`](./HLT.md) — Halt CPU

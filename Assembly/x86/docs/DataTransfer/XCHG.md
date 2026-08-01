# XCHG — Exchange

## Syntax

```asm
XCHG operand1, operand2
```

## Description

Atomically swaps the values of two operands. At least one operand must be a register. When used with a memory operand, XCHG automatically asserts the LOCK prefix — making it inherently atomic even without the `LOCK` prefix written explicitly.

## Flags Affected

None.

## Examples

```asm
; Swap two registers
XCHG eax, ebx             ; eax <-> ebx

; Swap register with memory (implicitly atomic)
XCHG eax, [counter]       ; atomic swap with memory location

; Classic no-temp swap
; Before: eax = A, ebx = B
XCHG eax, ebx
; After:  eax = B, ebx = A

; 8-bit swap
XCHG al, bl

; 16-bit swap
XCHG ax, bx
```

## XCHG as a Spinlock

```asm
; Simple test-and-set spinlock
; lock_var is 0 = free, 1 = locked
spin_lock:
    MOV  eax, 1
    XCHG eax, [lock_var]  ; atomically set lock, get old value
    TEST eax, eax
    JNZ  spin_lock         ; if old value was 1, loop (still locked)
    ; critical section here
spin_unlock:
    MOV  dword [lock_var], 0
```

## XCHG eax, eax (NOP encoding)

```asm
; XCHG eax, eax encodes as a single byte 0x90 — the classic NOP
XCHG eax, eax             ; equivalent to NOP
```

## Performance Note

- `XCHG reg, mem` is **slow** due to the implied LOCK prefix (bus lock or cache-line lock).
- For pure register swaps, XCHG is fine.
- For concurrent data structures, prefer `CMPXCHG` (compare-and-swap) or `LOCK XADD` when possible.

## Notes

- The implicit LOCK on memory operands makes XCHG safe for multi-threaded use without adding the prefix manually.
- Both operands must be the same size.
- Cannot exchange two memory locations.

## See Also

- [`MOV`](./MOV.md) — Move data
- [`PUSH`](./PUSH.md) / [`POP`](./POP.md) — Stack operations
- `CMPXCHG` — Compare and exchange (for lock-free algorithms)

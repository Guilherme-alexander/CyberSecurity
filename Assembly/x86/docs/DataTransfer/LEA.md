# LEA — Load Effective Address

## Syntax

```asm
LEA destination, source
```

## Description

Computes the **address** of `source` (a memory expression) and stores it in `destination`. Unlike `MOV`, it does **not** access memory — it only calculates the address. This makes LEA ideal for pointer arithmetic and fast multiplication.

## Flags Affected

None.

## Examples

```asm
; Load address of a variable
LEA rax, [my_array]       ; rax = address of my_array

; Pointer arithmetic — offset from base pointer
LEA rax, [rbp-16]         ; rax = rbp - 16 (local variable address)

; Pass address of local buffer as argument (System V ABI)
LEA rdi, [rbp-64]         ; arg1 = &buffer
CALL some_function

; Fast multiply by small constants using scale factors
LEA eax, [eax + eax*2]   ; eax = eax * 3
LEA eax, [eax*4]          ; eax = eax * 4
LEA eax, [eax + eax*4]   ; eax = eax * 5
LEA eax, [eax*8]          ; eax = eax * 8
LEA eax, [eax + eax*8]   ; eax = eax * 9

; Multi-component address expression
; (base + index*scale + displacement)
LEA rax, [rbx + rcx*4 + 8]  ; rax = rbx + rcx*4 + 8

; String / array indexing
LEA rbx, [rax + 1]        ; rbx = address of next element
```

## LEA vs MOV

```asm
section .data
  value dd 99

; MOV loads the VALUE at the address:
MOV eax, [value]          ; eax = 99

; LEA loads the ADDRESS itself:
LEA eax, [value]          ; eax = address where 99 is stored
```

## Use as Fast Arithmetic

```asm
; Equivalent to: eax = ebx + 7, without affecting flags
LEA eax, [ebx + 7]

; Equivalent to: eax = ebx + ecx, without affecting flags
LEA eax, [ebx + ecx]

; Shift-add in one instruction
LEA eax, [eax*2 + 5]     ; eax = eax*2 + 5
```

## Notes

- The source operand **must be a memory reference** `[...]` syntactically, but no memory access occurs.
- In 64-bit mode, LEA with a 32-bit destination register **zero-extends** the result into the 64-bit register.
- Compilers frequently emit LEA for pointer increments and arithmetic on loop counters because it avoids flag updates and has favourable encoding.
- LEA supports the full SIB (Scale-Index-Base) addressing mode: `[base + index*scale + disp]` where scale ∈ {1, 2, 4, 8}.

## See Also

- [`MOV`](./MOV.md) — Move (actually reads/writes memory)
- [`ADD`](../Arithmetic/ADD.md) — Addition (modifies flags)
- [`IMUL`](../Arithmetic/IMUL.md) — Signed multiply

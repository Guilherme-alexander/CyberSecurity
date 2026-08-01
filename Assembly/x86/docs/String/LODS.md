# LODS — Load String

## Syntax

```asm
LODSB           ; AL  = [RSI], RSI += 1
LODSW           ; AX  = [RSI], RSI += 2
LODSD           ; EAX = [RSI], RSI += 4
LODSQ           ; RAX = [RSI], RSI += 8
```

## Description

Loads a value from the address in RSI into AL/AX/EAX/RAX, then advances RSI. Typically used in loops to process a string or array element by element. The `REP` prefix is rarely useful here (would just overwrite AL repeatedly), so LODS is nearly always used without REP.

## Examples

```asm
; Iterate over a byte array, processing each element
CLD
LEA  rsi, [byte_array]
MOV  rcx, ARRAY_LEN
.loop:
    LODSB                 ; al = [rsi++]
    ; process al here...
    CALL process_byte
    DEC  rcx
    JNZ  .loop

; Custom strlen (find null terminator)
CLD
LEA  rsi, [string]
.find_null:
    LODSB                 ; al = [rsi++]
    TEST al, al
    JNZ  .find_null
; rsi now points one byte past the null terminator
LEA  rax, [string]
SUB  rsi, rax             ; length = end - start - 1 (subtract 1 for null byte)
DEC  rsi

; Case conversion: uppercase ASCII string to lowercase
CLD
LEA  rsi, [str]
LEA  rdi, [str]           ; in-place
.convert:
    LODSB                 ; al = [rsi++]
    TEST  al, al
    JZ    .done
    CMP   al, 'A'
    JB    .store
    CMP   al, 'Z'
    JA    .store
    OR    al, 0x20        ; set bit 5: uppercase -> lowercase
.store:
    STOSB                 ; [rdi++] = al
    JMP   .convert
.done:
```

## Notes

- RSI is the implicit **source** register (think: "S" = Source, "I" = Index).
- LODS is most useful in byte-processing loops where you process each element in AL.
- There is no REP form that makes practical sense — REP would just discard every element but the last.

## See Also

- [`STOS`](./STOS.md) — Store to string (write AL/AX/EAX to [RDI])
- [`MOVSB`](./MOVSB.md) — Copy byte from [RSI] to [RDI]
- [`SCAS`](./SCAS.md) — Scan string (compare AL with [RDI])

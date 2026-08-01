; syscall_amd64.asm - Implementação dos syscalls para x64
; Compilar com: nasm -f win64 syscall_amd64.asm -o syscall_amd64.obj

BITS 64
DEFAULT REL

section .text

%define maxargs 16
%define shadow  32          ; shadow space obrigatório ABI Windows x64

; ─────────────────────────────────────────────────────────────────────────────
; execIndirectSyscallASM(callID uint16, pSyscall uintptr,
;                        argsPtr uintptr, argsLen uint64) uint32
;
; Parâmetros (Windows x64):
;   CX  = callID    — número da syscall (16 bits)
;   RDX = pSyscall  — ponteiro para o stub da syscall (função a chamar)
;   R8  = argsPtr   — ponteiro para o array de argumentos
;   R9  = argsLen   — número de argumentos
; ─────────────────────────────────────────────────────────────────────────────
global execIndirectSyscallASM
execIndirectSyscallASM:
    push rbp
    mov  rbp, rsp

    ; salvar registradores callee-saved (Windows x64)
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    ; 8 pushes * 8 = 64 bytes → RSP alinhado em 16

    ; carregar callID em RAX
    xor rax, rax
    mov ax, cx              ; callID (16 bits) → RAX

    ; salvar ponteiro do stub (RDX será sobrescrito abaixo)
    mov r12, rdx            ; r12 = pSyscall

    ; salvar argsPtr e argsLen em registradores preservados
    mov r13, r8             ; r13 = argsPtr
    mov r14, r9             ; r14 = argsLen

    ; SetLastError(0) via TEB
    mov rdi, gs:[0x30]
    mov dword [rdi + 0x68], 0

    ; alocar espaço para args + shadow space
    sub rsp, maxargs * 8 + shadow

    ; nenhum argumento? vai direto pra chamada
    test r14, r14
    jz   .ind_jumpcall

    ; <= 4 args: só carregar nos registradores
    cmp r14, 4
    jle .ind_loadregs

    ; > maxargs: crash proposital
    cmp r14, maxargs
    jbe .ind_copyargs
    int 3

.ind_copyargs:
    ; copiar args extras para a pilha (acima do shadow space)
    lea rdi, [rsp + shadow]
    mov rsi, r13            ; fonte = argsPtr
    mov rcx, r14            ; contador = argsLen
    cld
    rep movsq
    lea rsi, [rsp + shadow] ; rsi aponta para os args na pilha

.ind_loadregs:
    ; carregar primeiros 4 args nos registradores
    mov rcx, [r13 + 0]
    mov rdx, [r13 + 8]
    mov r8,  [r13 + 16]
    mov r9,  [r13 + 24]

    ; espelhar em XMM (caso sejam floats — ABI Windows)
    movq xmm0, rcx
    movq xmm1, rdx
    movq xmm2, r8
    movq xmm3, r9

.ind_jumpcall:
    call r12                ; chama o stub indiretamente

    ; restaurar pilha
    add rsp, maxargs * 8 + shadow

    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx

    ; RAX já contém o NTSTATUS de retorno
    pop rbp
    ret


; ─────────────────────────────────────────────────────────────────────────────
; execDirectSyscallASM(callID uint16, argsPtr uintptr, argsLen uint64) uint32
;
; Parâmetros (Windows x64):
;   CX  = callID   — número da syscall
;   RDX = argsPtr  — ponteiro para o array de argumentos
;   R8  = argsLen  — número de argumentos
; ─────────────────────────────────────────────────────────────────────────────
global execDirectSyscallASM
execDirectSyscallASM:
    push rbp
    mov  rbp, rsp

    ; salvar registradores callee-saved
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    ; 8 pushes * 8 = 64 bytes → RSP alinhado em 16

    ; carregar callID em RAX
    xor rax, rax
    mov ax, cx              ; callID → RAX

    ; salvar argsPtr e argsLen
    mov r12, rdx            ; r12 = argsPtr
    mov r13, r8             ; r13 = argsLen

    ; SetLastError(0) via TEB
    mov rdi, gs:[0x30]
    mov dword [rdi + 0x68], 0

    ; alocar espaço para args + shadow space
    sub rsp, maxargs * 8 + shadow

    ; <= 4 args: só carregar registradores
    cmp r13, 4
    jle .dir_loadregs

    ; > maxargs: crash
    cmp r13, maxargs
    jbe .dir_copyargs
    int 3

.dir_copyargs:
    ; copiar args extras para a pilha
    lea rdi, [rsp + shadow]
    mov rsi, r12            ; fonte = argsPtr
    mov rcx, r13            ; contador = argsLen
    cld
    rep movsq
    lea rsi, [rsp + shadow]

.dir_loadregs:
    ; carregar primeiros 4 args
    mov rcx, [r12 + 0]
    mov rdx, [r12 + 8]
    mov r8,  [r12 + 16]
    mov r9,  [r12 + 24]

    ; espelhar em XMM
    movq xmm0, rcx
    movq xmm1, rdx
    movq xmm2, r8
    movq xmm3, r9

    ; Windows kernel lê arg1 de R10, não RCX (SYSCALL destrói RCX)
    mov r10, rcx
    syscall

    ; restaurar pilha
    add rsp, maxargs * 8 + shadow

    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx

    ; RAX = NTSTATUS
    pop rbp
    ret

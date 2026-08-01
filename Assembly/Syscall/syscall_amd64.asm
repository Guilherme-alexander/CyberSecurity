; syscall_amd64.asm - Implementação dos syscalls para x64
; Compilar com: nasm -f win64 syscall_amd64.asm -o syscall_amd64.obj

BITS 64
DEFAULT REL

section .text

%define maxargs 16

global execIndirectSyscallASM
execIndirectSyscallASM:
    push rbp
    mov rbp, rsp
    
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    
    xor rax, rax
    mov ax, cx
    
    mov r11, rdx
    
    mov rdi, gs:[0x30]
    mov dword [rdi + 0x68], 0
    
    sub rsp, maxargs * 8
    
    cmp r9, 0
    je .jumpcall
    
    cmp r9, 4
    jle .loadregs
    
    cmp r9, maxargs
    jbe .copyargs
    int 3
    
.copyargs:
    mov rdi, rsp
    mov rsi, r8
    mov rcx, r9
    cld
    rep movsq
    mov rsi, rsp
    
.loadregs:
    mov rcx, [rsi]
    mov rdx, [rsi + 8]
    mov r8, [rsi + 16]
    mov r9, [rsi + 24]
    
    movq xmm0, rcx
    movq xmm1, rdx
    movq xmm2, r8
    movq xmm3, r9
    
.jumpcall:
    call r11
    
    add rsp, maxargs * 8
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    
    mov rax, rax
    pop rbp
    ret

global execDirectSyscallASM
execDirectSyscallASM:
    push rbp
    mov rbp, rsp
    
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    
    xor rax, rax
    mov ax, cx
    
    mov rdi, gs:[0x30]
    mov dword [rdi + 0x68], 0
    
    sub rsp, maxargs * 8
    
    cmp r8, 4
    jle .loadregs
    
    cmp r8, maxargs
    jbe .copyargs
    int 3
    
.copyargs:
    mov rdi, rsp
    mov rsi, rdx
    mov rcx, r8
    cld
    rep movsq
    mov rsi, rsp
    
.loadregs:
    mov rcx, [rsi]
    mov rdx, [rsi + 8]
    mov r8, [rsi + 16]
    mov r9, [rsi + 24]
    
    movq xmm0, rcx
    movq xmm1, rdx
    movq xmm2, r8
    movq xmm3, r9
    
    mov r10, rcx
    syscall
    
    add rsp, maxargs * 8
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    
    mov rax, rax
    pop rbp
    ret

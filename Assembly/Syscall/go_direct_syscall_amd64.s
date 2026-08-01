#define maxargs 16

// Go Assembly
// bypassar de segurança (EDR/AV) Hook ntdll.dll SYSCALL kernel
// x86-64 - Windows 64 bits
// ┌─────────────────────────────────────────────────┐
// │                execDirectSyscall                │
// │                                                 │
// │  1. Carrega número da syscall em RAX            │
// │  2. Lê slice variádico (ponteiro + tamanho)     │
// │  3. Zera LastError no TEB via GS:0x30           │
// │  4. Aloca espaço na pilha para até 16 args      │
// │  5. Se > 4 args: copia tudo para a pilha        │
// │  6. Carrega args 1-4 em RCX, RDX, R8, R9        │
// │  7. Espelha em XMM0-XMM3 (por segurança)        │
// │  8. Copia RCX → R10 (kernel lê de R10)          │
// │  9. SYSCALL → entra no kernel NT diretamente    │
// │  10. Retorna NTSTATUS em errcode                │
// └─────────────────────────────────────────────────┘

// func execDirectSyscall(callID uint16, argh ...uintptr) (errcode uint32)
TEXT ·execDirectSyscall(SB), $0-56
	XORQ AX,AX
	MOVW callid+0(FP), AX
	PUSHQ CX

	//put variadic pointer into SI
	MOVQ argh_base+8(FP),SI

	//put variadic size into CX
	MOVQ argh_len+16(FP),CX

	// SetLastError(0).
	MOVQ	0x30(GS), DI
	MOVL	$0, 0x68(DI)
	SUBQ	$(maxargs*8), SP	// room for args

	// Fast version, do not store args on the stack.
	CMPL	CX, $4
	JLE	loadregs

	// Check we have enough room for args.
	CMPL	CX, $maxargs
	JLE	2(PC)
	INT	$3			// not enough room -> crash

	// Copy args to the stack.
	MOVQ	SP, DI
	CLD
	REP; MOVSQ
	MOVQ	SP, SI

	//move the stack pointer????? why????
	SUBQ	$8, SP

loadregs:
	// Load first 4 args into correspondent registers.
	MOVQ	0(SI), CX
	MOVQ	8(SI), DX
	MOVQ	16(SI), R8
	MOVQ	24(SI), R9

	// Floating point arguments are passed in the XMM
	// registers. Set them here in case any of the arguments
	// are floating point values. For details see
	//	https://msdn.microsoft.com/en-us/library/zthk2dkh.aspx
	MOVQ	CX, X0
	MOVQ	DX, X1
	MOVQ	R8, X2
	MOVQ	R9, X3

	MOVQ    CX, R10
	SYSCALL
	ADDQ	$((maxargs+1)*8), SP

	POPQ	CX
	MOVL	AX, errcode+32(FP)
	RET

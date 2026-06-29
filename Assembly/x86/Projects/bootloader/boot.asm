; ================================================================
; BOOTLOADER SIMPLES - MODO REAL 16 BITS
; ================================================================
; Este código é um bootloader que será carregado pela BIOS
; na memória RAM no endereço 0x7C00
; ================================================================

; Diretiva que informa ao montador (NASM) que o código será
; executado em modo de 16 bits (modo real do processador)
[BITS 16]

; Diretiva que define o endereço de origem (offset) onde o
; bootloader será carregado na memória. A BIOS sempre carrega
; o setor de boot no endereço físico 0x7C00 (segmento 0x0000,
; offset 0x7C00)
[ORG 0x7c00]

; ================================================================
; CONSTANTES PARA A GDT (Global Descriptor Table)
; ================================================================
; Define os índices dos segmentos na GDT
; Cada descritor de segmento tem 8 bytes
; CODE_OFFSET = 0x8 (8 bytes) -> primeiro descritor após o nulo
; DATA_OFFSET = 0x10 (16 bytes) -> segundo descritor após o nulo
; 
; Esses offsets são usados para carregar os seletores de segmento
; nos registradores quando entrarmos no modo protegido
CODE_OFFSET equ 0x8         ; Offsets para o descritor de código
DATA_OFFSET equ 0x10        ; Offsets para o descritor de dados

KERNEL_LOAD_SEG equ 0x1000
KERNEL_START_ADDR equ 0x100000

; ================================================================
; PONTO DE ENTRADA DO BOOTLOADER
; ================================================================
start:
    mov ax, 0x00            ; Move 0x0000 para o registrador AX
    mov ds, ax              ; DS (Data Segment) - aponta para dados
    mov es, ax              ;ES (Extra Segment) - aponta para dados
    mov ss, ax              ; SS (Stack Segment) - aponta para a 
    mov sp, 0x7c00

    ; Reativa as interrupções depois que toda a configuração
    ; inicial foi concluída com segurança
    sti                     ; Enable Interrupts (Habilita Interrupções)

    ; LOAD KERNEL
    mov bx, KERNEL_LOAD_SEG
    mov dh, 0x00
    mov dl, 0x80
    mov cl, 0x02
    mov ch, 0x00
    mov ah, 0x02
    mov al, 8
    int 0x13

    jc disk_read_error



; ================================================================
; TRANSIÇÃO PARA O MODO PROTEGIDO (PROTECTED MODE - 32 BITS)
; ================================================================
load_PM:
    ; Desabilita interrupções novamente - durante a transição
    ; para o modo protegido, as interrupções da BIOS (modo real)
    ; não podem ser usadas, então desabilitamos para evitar problemas
    cli

    ; LGDT - Load Global Descriptor Table
    ; Carrega a tabela GDT na memória. A GDT define os segmentos
    ; de memória que serão usados no modo protegido
    lgdt [gdt_descriptor]   ; Carrega o descritor da GDT

    ; Agora vamos ativar o modo protegido
    ; O registrador CR0 (Control Register 0) controla o modo do CPU
    ; O bit 0 (PE - Protection Enable) habilita o modo protegido
    mov eax, cr0            ; Move o valor de CR0 para EAX
    or al, 1                ; Faz OR com 1 - ativa o bit 0 (PE)
    mov cr0, eax            ; Move de volta para CR0 - AGORA ESTAMOS NO MODO PROTEGIDO!

    ; Salto far (far jump) para limpar o pipeline da CPU e 
    ; carregar o seletor de segmento de código (CODE_OFFSET)
    ; Esse salto é necessário porque após ativar o modo protegido,
    ; a CPU ainda está executando instruções em modo real no pipeline
    ; O salto força a CPU a recarregar o pipeline com instruções de 32 bits
    jmp CODE_OFFSET:PModeMain

disk_read_error:
	hlt

; ================================================================
; DADOS DO PROGRAMA
; ================================================================
; Define a mensagem que será impressa. A string é definida com
; aspas simples e terminada com um byte nulo (0) que serve como
; marcador de fim de string para nossa rotina de impressão
msg: db 'Hello World!', 0   ; db = Define Byte (define bytes na memória)

; ================================================================
; GDT - GLOBAL DESCRIPTOR TABLE (Tabela de Descritores Globais)
; ================================================================
; A GDT é uma tabela que descreve os segmentos de memória disponíveis
; no modo protegido. Cada entrada tem 8 bytes e define:
; - Endereço base do segmento
; - Limite (tamanho) do segmento
; - Tipo de segmento (código, dados, etc.)
; - Privilégios de acesso (Ring 0 a 3)

gdt_start:
    ; ------------------------------------------------------------
    ; DESCRITOR NULO (OBRIGATÓRIO)
    ; ------------------------------------------------------------
    ; O primeiro descritor da GDT deve ser nulo (todos zeros)
    ; É usado como "ponto de segurança" - se um registrador de
    ; segmento for carregado com 0, a CPU gera uma exceção
    dd 0x0                  ; dd = Define Double Word (4 bytes) -> 00 00 00 00
    dd 0x0                  ; dd = Define Double Word (4 bytes) -> 00 00 00 00

    ; ------------------------------------------------------------
    ; DESCRITOR DE SEGMENTO DE CÓDIGO (CODE SEGMENT)
    ; ------------------------------------------------------------
    ; Este descritor define um segmento de memória para código
    ; executável (instruções do programa)
    db 0xFFFF               ; LIMIT (bits 0-7) - Limite inferior do segmento
    db 0x0000               ; BASE (bits 0-7) - Base inferior do segmento
    db 0x00                 ; BASE (bits 8-15) - Base média do segmento
    db 10011010b            ; ACCESS BYTE - Byte de acesso:
                            ; 1   = Segmento presente (P)
                            ; 0   = Nível de privilégio 0 (DPL - Descriptor Privilege Level)
                            ; 0   = Nível de privilégio 0 (DPL)
                            ; 1   = Tipo de descritor (DT) - 1 = código/dados
                            ; 1   = Tipo de segmento (Type) - 1 = código
                            ; 0   = Conforme (C) - 0 = não conforme
                            ; 1   = Acessível (R) - 1 = pode ser lido
                            ; 0   = Acessado (A) - 0 = não acessado ainda
    db 11001111b            ; FLAGS + LIMIT (bits 16-19):
                            ; 1   = Granularidade (G) - 1 = página (4KB)
                            ; 1   = Tamanho (D) - 1 = 32 bits (modo protegido)
                            ; 0   = Modo longo (L) - 0 = modo 32 bits
                            ; 0   = Reservado (AVL)
                            ; 1111 = Limite (bits 16-19) - limite superior
    db 0x00                 ; BASE (bits 24-31) - Base superior do segmento

    ; ------------------------------------------------------------
    ; DESCRITOR DE SEGMENTO DE DADOS (DATA SEGMENT)
    ; ------------------------------------------------------------
    ; Este descritor define um segmento de memória para dados
    ; (variáveis, pilha, etc.)
    dw 0xFFFF               ; LIMIT (bits 0-15) - Limite completo
    dw 0x0000               ; BASE (bits 0-15) - Base completa
    db 0x00                 ; BASE (bits 16-23) - Base média
    db 10010010b            ; ACCESS BYTE:
                            ; 1   = Presente (P)
                            ; 0   = DPL - nível 0
                            ; 0   = DPL - nível 0
                            ; 1   = DT - 1 = código/dados
                            ; 0   = Tipo - 0 = dados
                            ; 0   = Estendido (E) - 0 = não estendido
                            ; 1   = Escrita (W) - 1 = permite escrita
                            ; 0   = Acessado (A)
    db 11001111b            ; FLAGS + LIMIT (mesmo do código)
    db 0x00                 ; BASE (bits 24-31)

gdt_end:                    ; Marca o fim da GDT

; ------------------------------------------------------------
; DESCRITOR DA GDT
; ------------------------------------------------------------
; Esta estrutura é usada pela instrução LGDT
; Contém o tamanho da GDT (em bytes - 1) e o endereço de início
gdt_descriptor:
    dw gdt_end - gdt_start - 1  ; Tamanho da GDT - 1 (em bytes)
                                 ; Calculado automaticamente com labels
    dw gdt_start                 ; Endereço de início da GDT

; ================================================================
; MODO PROTEGIDO - CÓDIGO 32 BITS
; ================================================================
; Diretiva que informa ao montador que a partir daqui o código
; será executado em modo de 32 bits (modo protegido)
[BITS 32]

PModeMain:
    ; Agora no modo protegido, os registradores de segmento
    ; precisam ser carregados com os seletores da GDT
    ; Usamos DATA_OFFSET (0x10) para os segmentos de dados
    mov ax, DATA_OFFSET     ; Carrega o seletor de dados em AX
    mov ds, ax              ; DS = segmento de dados
    mov es, ax              ; ES = segmento de dados
    mov fs, ax              ; FS = segmento de dados (extra)
    mov ss, ax              ; SS = segmento de pilha
    mov gs, ax              ; GS = segmento de dados (extra)

    ; Configura a pilha no modo protegido
    ; EBP (Base Pointer) e ESP (Stack Pointer) são registradores de 32 bits
    ; 0x9C00 é um endereço seguro para a pilha (abaixo da memória da BIOS)
    mov ebp, 0x9C00         ; EBP aponta para o topo da pilha
    mov esp, ebp            ; ESP = EBP (pilha começa em 0x9C00)

    ; ============================================================
    ; ATIVA A LINHA A20 (A20 LINE)
    ; ============================================================
    ; A linha A20 é a 21ª linha do barramento de endereços
    ; Em modo real, a linha A20 é desabilitada (emulando o 8086)
    ; Para acessar mais de 1MB de memória no modo protegido,
    ; precisamos ativar a linha A20
    ; 
    ; Método usado: Controlador de teclado (porta 0x92)
    ; 0x92 é uma porta do chipset que controla a linha A20
    in al, 0x92             ; Lê o valor atual da porta 0x92
    or al, 2                ; Ativa o bit 1 (linha A20)
    out 0x92, al            ; Escreve de volta na porta

    ; Loop infinito - trava a execução aqui
    ; $ = posição atual (endereço desta instrução)
    ; jmp $ = salta para si mesmo, causando um loop infinito
    jmp CODE_OFFSET:KERNEL_START_ADDR   ; Fica preso neste loop para sempre
    

; ================================================================
; PREENCHIMENTO DO SETOR DE BOOT
; ================================================================
; O setor de boot (boot sector) tem que ter exatamente 512 bytes.
; Os dois últimos bytes devem ser a assinatura 0xAA55 para que a
; BIOS reconheça que é um setor de boot válido.
;
; Cálculo: 510 - ($ - $$)
; $ = posição atual (onde estamos agora)
; $$ = posição do início do código (start)
; ($ - $$) = tamanho do código até agora
; 510 - ($ - $$) = quantos bytes ainda precisamos preencher
;                  para chegar a 510 bytes (os 2 finais serão 0xAA55)
;
; O comando TIMES repete a instrução seguinte N vezes.
; Neste caso, preenche com zeros (db 0) até completar 510 bytes
times 510 - ($ - $$) db 0

; ================================================================
; ASSINATURA DO SETOR DE BOOT
; ================================================================
; Os dois últimos bytes do setor de boot devem ser 0x55 e 0xAA
; (nessa ordem, formando a palavra 0xAA55 quando lida como little-endian)
; A BIOS verifica essa assinatura para confirmar que o dispositivo
; realmente contém um setor de boot válido
dw 0xAA55                  ; dw = Define Word (define palavra de 2 bytes)

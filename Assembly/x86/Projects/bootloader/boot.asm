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
; PONTO DE ENTRADA DO BOOTLOADER
; ================================================================
start:
    ; Desabilita as interrupções enquanto configuramos os
    ; registradores de segmento. Isso evita que uma interrupção
    ; ocorra no meio da configuração e cause problemas
    cli                     ; Clear Interrupts (Limpa/Desabilita Interrupções)

    ; Configura os registradores de segmento para apontar para
    ; o segmento 0x0000. Como o ORG é 0x7C00, o endereço físico
    ; será: (segmento * 16) + offset = (0x0000 * 16) + 0x7C00 = 0x7C00
    mov ax, 0x00            ; Move 0x0000 para o registrador AX
    mov ds, ax              ; DS (Data Segment) - aponta para dados
    mov es, ax              ; ES (Extra Segment) - aponta para dados extras
    mov ss, ax              ; SS (Stack Segment) - aponta para a pilha

    ; Configura o ponteiro de pilha (SP - Stack Pointer) para o
    ; endereço 0x7C00. Como a pilha cresce para baixo (endereços
    ; decrescentes), ela ficará entre 0x7C00 e 0x0000, não
    ; conflitando com nosso código que está em 0x7C00 para cima
    mov sp, 0x7c00

    ; Reativa as interrupções depois que toda a configuração
    ; inicial foi concluída com segurança
    sti                     ; Enable Interrupts (Habilita Interrupções)

    ; Carrega o endereço da mensagem no registrador SI (Source Index)
    ; SI será usado como ponteiro para a string que queremos imprimir
    mov si, msg

; ================================================================
; ROTINA PARA IMPRIMIR UMA STRING NA TELA
; ================================================================
print:
    ; Instrução LODSB - Load String Byte
    ; Carrega um byte do endereço apontado por DS:SI para o
    ; registrador AL e automaticamente incrementa SI em 1
    ; Exemplo: se DS:SI aponta para 'H', AL recebe 'H' e SI avança
    lodsb

    ; Compara o byte carregado em AL com zero (0). Em assembly,
    ; strings sempre terminam com um byte nulo (0) para indicar
    ; o fim da string. Nossa string 'Hello World!' termina com ', 0'
    cmp al, 0               ; Compara AL com 0
    je done                 ; JE = Jump if Equal. Se AL == 0, fim da string

    ; Se não for o fim da string, vamos imprimir o caractere
    ; Usamos a interrupção 0x10 da BIOS - Serviços de Vídeo
    ; Função 0x0E = Teletype Output - imprime um caractere na tela
    mov ah, 0x0E            ; AH = 0x0E (função de imprimir caractere)
    int 0x10                ; Chama a interrupção de vídeo da BIOS

    ; Volta para o início do loop para imprimir o próximo caractere
    jmp print

; ================================================================
; FINALIZAÇÃO - PARA A EXECUÇÃO
; ================================================================
done:
    ; Desabilita interrupções novamente antes de parar
    ; Não queremos que nada interrompa o sistema enquanto ele
    ; está "parado"
    cli

    ; HLT - Halt the processor (Para a execução da CPU)
    ; A CPU entra em estado de espera (halt) até a próxima
    ; interrupção. Como desabilitamos as interrupções, a CPU
    ; ficará parada para sempre (ou até o usuário reiniciar)
    hlt                     ; Halt - Para a execução do processador

; ================================================================
; DADOS DO PROGRAMA
; ================================================================
; Define a mensagem que será impressa. A string é definida com
; aspas simples e terminada com um byte nulo (0) que serve como
; marcador de fim de string para nossa rotina de impressão
msg: db 'Hello World!', 0   ; db = Define Byte (define bytes na memória)

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

/* ================================================================
 * SCRIPT DE LINKER PARA O KERNEL
 * ================================================================
 * Este script define como o linker deve organizar as seções
 * do kernel na memória, definindo endereços e alinhamentos.
 * ================================================================ */

/* Ponto de entrada do programa (deve ser global no assembly) */
ENTRY(_start)

/* Formato de saída: binário puro (sem cabeçalho ELF) */
OUTPUT_FORMAT(binary)

/* Definição das seções */
SECTIONS
{
    /* ============================================================
     * ENDEREÇO BASE DO KERNEL
     * ============================================================
     * O kernel será carregado em 0x01000000 (16 MB).
     * Isso deve coincidir com o endereço para onde o bootloader
     * salta (KERNEL_START_ADDR em boot.asm).
     * 
     * ATENÇÃO: Em boot.asm você definiu KERNEL_START_ADDR equ 0x100000
     * (1 MB), mas aqui usa 0x01000000 (16 MB). Isso é inconsistente!
     * Recomendo usar 0x100000 (1 MB) em ambos.
     */
    . = 0x01000000;

    /* ============================================================
     * SEÇÃO DE CÓDIGO (.text)
     * ============================================================
     * Contém as instruções executáveis do kernel.
     * ALIGN(4096) alinha em página de 4 KB (útil para paginação futura)
     */
    .text : ALIGN(4096)
    {
        *(.text)   /* Inclui todas as seções .text de todos os objetos */
    }

    /* ============================================================
     * SEÇÃO DE DADOS SOMENTE LEITURA (.rodata)
     * ============================================================
     * Contém constantes e strings literais.
     */
    .rodata : ALIGN(4096)
    {
        *(.rodata)   /* Atenção: faltava o ponto antes de rodata? Corrigi para *(.rodata) */
    }

    /* ============================================================
     * SEÇÃO DE DADOS INICIALIZADOS (.data)
     * ============================================================
     * Contém variáveis globais com valores iniciais.
     */
    .data : ALIGN(4096)
    {
        *(.data)   /* Inclui todas as seções .data */
    }

    /* ============================================================
     * SEÇÃO DE DADOS NÃO INICIALIZADOS (.bss)
     * ============================================================
     * Contém variáveis globais sem valor inicial (zeradas pelo loader).
     * ALIGN(4096) alinha para começar em página limpa.
     */
    .bss : ALIGN(4096)
    {
        *(COMMON)  /* Símbolos comuns (não inicializados) */
        *(.bss)    /* Seção .bss propriamente dita */
    }
}

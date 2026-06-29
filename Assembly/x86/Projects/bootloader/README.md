# BootLoader 
Assembly x86 de 16 bits (modo real).

1. `[BITS 16]` - Esta diretiva indica explicitamente que o código deve ser montado para modo de 16 bits.
2. `[ORG 0x7c00]` - Endereço de organização típico do bootloader no modo real (endereçamento segmentado de 16 bits).
3. Interrupção BIOS `int 0x10` - Esta é uma interrupção do BIOS que funciona no modo real de 16 bits.
4. `dw 0xAA55` - A assinatura do boot sector (palavra de 16 bits).

### x64:
#### Se você quisesse um bootloader para x64, precisaria:
- Configurar o modo protegido (`32 bits`)
- Configurar o modo longo (`64 bits`)
- Usar diretivas `[BITS 32]` e depois `[BITS 64]`
- Usar registradores de 64 bits como `rax`, `rsi`, `rsp`
- Configurar paginação e tabelas de descritores

```bash
# BUILD
$ make all
nasm -f bin ./src/boot.asm -o ./bin/boot.bin

# RUN
$ qemu-system-x86_64 -hda ./boot.bin
```

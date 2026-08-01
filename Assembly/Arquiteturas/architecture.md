# arquitetura x86

### A nomenclatura é confusa por razões históricas

### x86 — A origem (1978)

A Intel lançou o processador **8086** em 1978. A arquitetura ficou conhecida como **x86** porque todos os chips da época terminavam em "86": 8086, 80186, 80286, 80386, 80486...

Quando as pessoas falam "x86" hoje, geralmente estão se referindo à versão **32 bits** dessa arquitetura, introduzida com o **80386** em 1985. Também chamada de **IA-32**.

- Registradores de 32 bits: `EAX`, `EBX`, `ESP`, `EIP`...
- Endereça até **4 GB** de RAM
- Windows 32 bits, Linux i386

---

### x86-64 — A extensão para 64 bits (2003)

A **AMD** (não a Intel!) criou a extensão 64 bits da arquitetura x86 em 2003, chamando de **AMD64**. A Intel depois adotou e chamou de **Intel 64** ou **EM64T**.

O nome técnico correto é **x86-64**, mas você vai ver vários apelidos:

| Apelido | Quem usa |
|---------|----------|
| `x86-64` | Nome técnico oficial |
| `x64` | Microsoft / uso popular |
| `AMD64` | Linux, Debian, GCC |
| `Intel 64` | Intel |

- Registradores de 64 bits: `RAX`, `RBX`, `RSP`, `RIP`...
- Registradores novos: `R8` até `R15`
- Endereça até **16 exabytes** de RAM (na prática ~256 TB hoje)
- É **retrocompatível** com x86 de 32 bits

---

### x32 — O caso especial (raramente usado)

**x32** é uma ABI (Application Binary Interface) do Linux que combina o melhor dos dois mundos: roda em modo 64 bits mas usa **ponteiros de 32 bits** para economizar memória. Quase nunca é usada na prática, foi considerada um experimento.

---

## Resumo visual

```
1978        1985          2003
 │           │             │
8086        80386        AMD64
 │           │             │
x86    →   x86 (32-bit)  x86-64
           "IA-32"       "x64"
```

---

## Respondendo dúvidas

> **"Assembly x86 é arquitetura x64?"**

**Não exatamente.** x86 e x64 são parentes:

- **x86** = arquitetura de 32 bits (o "pai")
- **x64 / x86-64** = extensão de 64 bits do x86 (o "filho")

Estudando na documentação **x86-64** (64 bits), que é o que roda em qualquer computador moderno. O nome "x86" no título da pasta se refere à **família de arquiteturas**, não especificamente ao modo 32 bits.

Na prática hoje:
- Todo PC/Mac moderno roda **x86-64**
- Quando alguém diz "escrevi em assembly x86", provavelmente está falando de **x86-64**
- O modo 32 bits puro (`EAX`, `ESP`) ainda existe mas só aparece em sistemas legados ou bootloaders

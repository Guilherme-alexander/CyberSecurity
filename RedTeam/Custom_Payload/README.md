## Evitando Antivírus com Melhores Cargas Úteis do Meterpreter

Evitar antivírus é frequentemente uma arte pouco valorizada que pode fazer ou fracassar um teste de penetração. Produtos antivírus modernos podem detectar facilmente cargas úteis meterpreter e podem deixar um pentester acreditando falsamente que um sistema não é explorável.
Para aumentar nossa taxa geral de sucesso de exploração, criaremos um meterpreter personalizado reverse_tcp carga útil.
Para isso, primeiro precisaremos de algumas coisas:
Comunidade Visual Studio 2019 (Grátis): https://visualstudio.microsoft.com/downloads/ Metasploit Framework: https://github.com/rapid7/metasploit-framework

## TLDR

Vamos criar shellcode com msfvenom, codificar, colar em um template personalizado e entregar o binário compilado como um payload personalizado com metasploit.

## Shellcode do Windows: x86 ou x64?

Há alguns anos, era muito comum que binários x64 passassem despercebidos pelo Windows Defender, porém os produtos antivírus melhoraram muito recentemente e começaram a detectar cargas úteis de x64 meterpreter que testamos. Pouquíssimos codificadores suportam shellcode x64, o que reduz ainda mais nossa capacidade de criar cargas furtivas. Em nossos testes, descobrimos que construir cargas úteis x86 com o shikata_ga_nai resistiu ao maior teste do tempo e ainda consegue evitar a maioria dos motores AV.

## Cargas úteis Meterpreter: qual delas?

Você pode visualizar uma lista de cargas úteis executando , nós usaremos o **reverse_tpc** estagio Carga Útil: `msfvenom -l payloads`

```bash
windows/meterpreter/reverse_tcp                     Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Connect back to the attacker
```

>Nota: a carga útil selecionada `windows/meterpreter/reverse_tcp` é consideravelmente diferente da carga útil `windows/meterpreter_reverse_tcp`. A segunda indica que a carga útil está em estágio e se conectará de volta ao nosso manipulador para entregar toda a carga útil do meterpreter.

## Shellcode Encoder

Você pode visualizar todos os codificadores disponíveis executando `msfvenom -l encoders`. Vemos o maior sucesso usando várias iterações com x86/shikata_ga_nai.

```
    x86/shikata_ga_nai            excellent  Polymorphic XOR Additive Feedback Encoder
```

## Criando o shellcode com o Msfvenom

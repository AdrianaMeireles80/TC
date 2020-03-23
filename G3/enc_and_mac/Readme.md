# Guião 3 : Encrypt and MAC
## Contextualização
Uma parte deste guião 3 era conseguir utilizar o processo de **Encrypt and MAC**.
Neste ficheiro vamos explicar algumas decisões assim como descrever todos os processos.

## Justificação das opções tomadas
Para isto é necessário percebermos em que se baseia este processo de **Encrypt and MAC**.
Este processo baseia-se em calcularmos o MAC da mensagem de texto por encriptar (convenientemente designado por nós como *texto limpo*) e aplicar também o processo de encriptação sobre o texto limpo. Depois destes dois processos separados escrevemos num só ficheiro o criptograma e a tag do MAC calculado no mesmo ficheiro. Matemáticamente falando estamos na presença de duas fórmulas: 
- Criptograma:
  C=E(Kc,P)
- MAC:
  t=MAC(Km,P)
, onde Kc é equivalente à chave usada para a cifra, Km à chave usada para calcular o MAC e o P corresponde ao texto limpo.

### Encriptação
O processo de encriptação pode ser dividido em 3 partes:
- Geração de uma Key segundo uma password dada pelo utilizador
- Encriptação do texto limpo
- MAC do texto limpo

#### Gerar Key
Vai ser pedido ao utilizador uma password para ele fornecer.
Esta password vai ser utilizada para o método *PBKDF2HMAC* para gerar uma chave de 64 bytes, com um salt aleatório. 
Essa chave de 64 bytes vai ser dividida em duas chaves (com 32 bytes cada). Os primeiros 32 bytes vão dizer respeito à key para a cifra e os outros 32 bytes para a key do MAC.

#### Encriptação do texto limpo
Para encriptar vamos usar uma cifra CHACHA20. 
Geramos esta cifra com a chave de encriptação obtida no processo anterior e aplicamos a mesma sobre o texto limpo. Para gerarmos a cifra foi usado o método: `cypher = ChaCha20.new(key=enc_key)`, onde *enc_key* corresponde à chave. Já a pensar no processo inverso, guardamos na variável **enc_msg** o *nonce* da cifra e depois o texto encriptado:
```
enc_msg = enc_msg = cypher.nonce + cypher.encrypt(plaintext.read())
```
#### MAC do texto limpo
Para calcular o MAC do texto limpo vamos usar SHA-256.
Com a segunda key vamos criar uma Hash cujo *digestmod* é o SHA-256. Com o método `HMAC.new(mac_key,clean_text,digestmod=SHA256)` podemos calcular o MAC da mensagem limpa ( *clean_text* ), segundo a chave do MAC calculada no primeiro processo ( *mac_key* ) com o método de SHA256 ( *digestmod=SHA256* ). Este MAC vai ser transformado em hexadecimal (através do `HMAC.hexdigest()`) e depois para bytes (com o `encode()`). Este processo está presente com a linha de código:
```
mac_msg = mac.hexdigest().encode()
```

#### Ficheiro Final
Já tendo passado pelos 3 processos está na hora de compilar tudo no criptograma(ficheiro encriptado). Para isso decidimos colocar em primeiro o ***salt***, seguido do ***MAC*** e só depois o texto encriptado da mensagem. A razão de o fazermos é porque sabemos que tanto o salt, como o MAC têm tamanhos fixes (16 e 64 bytes respetivamente ) e tudo o resto é texto que nos interessa. 
Posto isto vemos que a mensagem final é construída através de:
```
with open("mensagem.enc","wb") as final_msg:
        final_msg.write(salt + mac_msg + enc_msg)
```

### Decriptação
O processo de decriptação pode ser dividido em 3 partes:
- Geração de uma Key segundo uma password dada pelo utilizador
- Tentativa de decriptação do texto encriptado
- Verificação do MAC do texto decriptado

#### Gerar Key
Tal como na encriptação vai ser pedido uma password ao utilizador.
Esta password vai ser utilizada para o método *PBKDF2HMAC* para gerar uma chave de 64 bytes, porém, para o processo de decriptação funcionar, será necessário ir buscar o **salt** utilizado para encriptação. Assim é necessário ir ao ficheiro encriptado e pegar nos primeiros 16 bytes:
```
with open("mensagem.enc","rb") as f:
        salt = f.read(16)
```
Com este **salt** é possível calcular a chave gerada na encriptação.
Essa chave de 64 bytes também aqui vai ser dividida em duas chaves (com 32 bytes cada). Os primeiros 32 bytes vão dizer respeito à key para a cifra e os outros 32 bytes para a key do MAC.

#### Decriptação do texto encriptado
Depois de termos obtido as chaves para a cifra e o MAC vamos começar por gerar a cifra e desencriptar a mensagem. Para esta cifra além da *key* já obtida vamos precisar do *nonce* da mesma (a cifra só funcionará quando é aplicado o mesmo nonce na mesma key). Como sabemos do processo de encriptação, o *nonce* foi guardado juntamente com a mensagem relevante. Assim o *nonce* desejado é obtido retirando os 8 primeiros bytes desse texto. Com isto podemos gerar a cifra desejada:
`cypher = ChaCha20.new(key=enc_key,nonce = enc_msg_nonce)` .
Após termos a cifra, desencriptamos a mensagem com o método ```cypher.decrypt(enc_msg)```.

#### MAC do texto desencriptado
Tendo nós em nossa posse o texto desencriptado falta verificar a integridade da mesma. Para isso vamos calcular o MAC do texto agora desencriptado: 
``` mac = HMAC.new(mac_key,cleantext,digestmod=SHA256) ```
e comparar com o MAC guardado com o texto encriptado: ``` mac.hexverify(mac_tag) ``` . Esta tag foi obtida lendo os 64 bytes após o salt.

#### Ficheiro Final
Se não houve corrupção de dados da mensagem encriptada e a password do utilizador for correta tanto os ficheiros **mensagem.txt** e **mensagem.dec** serão iguais.

### Pasta de Ataque
Para provarmos que o MAC é eficaz contra ataques de integridade criamos uma nova pasta com dois ficheiros **.py**: um para encriptar e outro para desencriptar, e ainda uma mensagem a ser encriptada. O ficheiro de desencriptação é igual ao anteriormente falado. No que toca à encriptação foi apenas adicionado um método que escreve texto ao fim do ficheiro. 
Posto isto o processo de encriptação corre perfeitamente bem. No que toca à desencriptação já não é isso que acontece visto que depois de calcular o MAC do texto desencriptado este não vai coincidir com o que está no criptograma, lançando assim ua mensagem de mensagem corrompida. 

## Dificuldades encontradas
Neste processo, que embora tenha sido simples, o mais complexo foi perceber como iríamos verificar a integridade com o MAC da mensagem. Após uma pequena reflexão foi bastante intuitivo que o processo correto seria aquele que nós aplicamos.
A isto apenas se juntou a aprendeizagem das novas bibliotecas usadas (CHACHA20 e HMAC-SHA256) visto que nunca tínhamos tido nenhum contacto anterior com as mesmas.

## Instruções
Para testarmos basta primeiramente introduzir na linha de comandos: `$ python3 encript.py` e depois para desencriptar: `$ python3 decript.py`. Para apagarmos ficheiros criados pelos dois processos basta correr : `$ make clean` .

## Conclusões
Concluímos assim que este método é eficaz contra a integridade, porém a cifra pode não ser assim tão segura. O facto de guardarmos o MAC do ficheiro de texto que contém a mensagem limpa permite aos atacantes perceber se dois textos vão ser iguais, pois o MAC deles vão ser iguais também. Assim se o atacante começar a identificar blocos, poderá levar um problema de confidencialidade.




# Guião 2

## Melhorias
Depois de uma conversa com o professor apercebemo-nos que tínhamos feito uma interpretação do exercício.
Assim decidimos melhorar o nosso guião para ir mais de encontro com o pedido.

### 1ª Versão
#### Encriptação

Nesta versão usamos uma derivação de PBKDF2HMAC para calcular um array de 32 bytes para ser usada como chava da cifra e um salt aleatóriamente gerado com 16 bytes. Tendo isto passamos o array de bytes para base64 para poder ser usada como semente de geração de uma cifra Fernet. Com essa cifra encriptamos a mensagem limpa. No ficheiro encriptado escrevemos primeiro o *salt* e só depois a mensagem já encriptada.

#### Decriptação

Para desencriptar a mensagem voltamos a usar a derivação de PBKDF2HMAC, mas deste vez não geramos o *salt* aleatório. Para valor do *salt* lemos os primeiros 16 bytes do ficheiro encriptado. Depois disso é esperado obter o mesmo array de 32 bytes. Com esse array voltamos a passar para base64, geramos a cifra Fernet com essa semente e desencriptamos o texto.

### 2ª Versão
#### Encriptação
Nesta versão usamos uma derivação de **Scrypt** . Neste processo voltamos a pegar no array de bytes gerado, convertemos em base64, geramos a cifra Fernet e encriptamos a mensagem. Além disso guardamos o salt no ficheiro *salt.Keystore* .
#### Decriptação
O processo de decriptação desta versão é muito idêntico ao da versão anterior, mas desta vez pegamos no salt guardado no *salt.Keystore*. 

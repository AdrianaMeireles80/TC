# Guião 7

## Contextualização
Decidimos refazer o Guião 6 usando o modo GCM da biblioteca cryptography. Posteriormente, implementámos a funcionalidade da assinatura digital (RSA) análoga ao protocolo Station-to-Station.

## Justificação das opções tomadas
Para conseguir atingir o objetivo proposto vamos reutilizar os ficheiros do **cliente** e do **servidor**. Vai ser necessário ainda criar um ficheiro novo que vai criar as chaves de assinatura de ambos. Quanto aos ficheiros reutilizados vamos explicar apenas as opções tomadas relativamente às partes novas introduzidas,visto que o resto foi explicado no guião anterior.

### Gerar chaves de assinatura
Foi-nos aconselhado a fazer a criação as chaves de assinatura antes de estarem a correr os processos de Cliente e Servidor. Assim no ficheiro [**generate_SignatureKeys.py**](../generate_SignatureKeys.py) dão se a criação dessas mesmas chaves.
Nesse ficheiro podemos distinguir 4 métodos diferentes em relação à criação de assinaturas digitais com RSA:
* `rsa.generate_private_key(public_exponent,key_size,backend)` - método responsável por criação de uma chave privada RSA. Esta chave privada é atribuída a uma entidade, por isso é necessário que este método seja chamado 2 vezes.

* `private_key.private_bytes(encoding,format,encryption_algorithm)` - associado à chave privada, este método é o responsável por transformar a chave privada em bytes para poder ser escrita num ficheiro.

* `private_key.public_key()` - diz respeito à criação de uma chave pública a partir de uma chave privada. Tal como o primeiro método referido, este vai ter de ser executado 2 vezes (uma por cada chave privada).

* `public_key.public_bytes(encoding,format)` - método que transforma a chave pública em bytes para também poder ser escrita num ficheiro.

Em resultado destes métodos serem chamados vamos ter 4 novos ficheiros que correspondem às chaves públicas e privadas do Servidor e do Cliente (um ficheiro por cada chave).

### Cliente e Servidor

Quanto ao cliente e ao servidor foram adicionados em cada um três variáveis de instância. Isto veio com a necessidade de guardar as próprias chaves públicas e privadas de assinatura e a chave pública de assinatura da outra entidade (que irá servir como argumento para provar a autenticidade). Assim antes de qualquer leitura ou envio de mensagens é invocado o método `readSignatureKeys()` que vai ler os ficheiros com as chaves e guardar nas variáveis de instância. 

Estando guardadas as chaves de assinatura necessárias, as primeiras trocas de mensagem têm de seguir um padrão.
Assim o cliente começa por enviar ao servidor a sua chave pública de encriptação. O servidor responde com a sua chave pública de encriptação também, juntamento com a assinatura aplicada às duas chaves públicas. O cliente responde ao servidor também com a assinatura aplicada às duas chaves. Com isto temos o protocolo Station-to-Station. Por uma questão de conveniência e facilidade, o servidor vai responder ao cliente com a mensagem "Ok!" juntamente com a assinatura aplicada à mensagem. A partir daí a troca de mensagens correrá normalmente.

Quanto ao processo de assinatura e validação da mesma, vamos usar dois métodos:
* `signature_sign(message)` - que recebendo uma mensagem, usufrui do método `private_key.sign(message,padding,algorithm)` para assinar a mensagem com a chave privada. Este método irá retornar a assinatura pretendida que irá ser concatenada com a mensagem a ser enviada à outra entidade.

* `signature_verify(message,signature)` - que recebe a mensagem e a assinatura a verficar, usufrui do método `public_key.verify(signature,message,padding,algorithm)` para verificar se a assinatura é correta. Se a assinatura não coincidir, é lançada uma exceção que avisa que a mensagem não é autenticada.


## Dificuldades encontradas
Houve dificuldade em entender a documentação da biblioteca.

## Instruções
Para testar este Guião são necessários 3 comandos. 
Abre-se um terminal:
* `python3 generate_SignatureKeys.py`
* `python3 servidor.py` 
Noutro terminal:
* `python3 cliente.py`

## Conclusões
Concluimos que com este processo conseguimos garantir a autenticidade da mensagem e com base neste objeitvo, achamos que este foi bem conseguido pelo trabalho desenvolvido.

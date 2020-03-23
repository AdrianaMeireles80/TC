## Contextualização
Para a realização deste trabalho foi criada uma chave aleatória baseada numa password através da 
implementação de uma função passwd(). Deste modo, foi usado o mecanismo PBKDF2-HMAC.
Posteriormente,é utilizado o método criptográfico AES block cipher com o modo EAX,CBC e CFB que permite que a mensagem seja cifrada.

## Justificação das opções tomadas

Como o mecanismo PBKDF2-HMAC já tinha sido usado anteriormente utilizamo-lo, mais uma vez, para gerar a chave aleatória.
Foram usados os modos EAX, CBC e CFD porque todos garantem confidencialidade e autenticação.
No entanto, apenas o modo EAX garante integridade da mensagem.

## Instruções
Para cada um dos modos é necessário usar os seguintes comandos explicitamente nesta ordem em diferentes terminais:

    python3 servidor.py - Executa o servidor
    python3 cliente.py - Executa um cliente

## Dificuldades Encontradas
Numa fase inicial foi necessário entender o processo de comunicação entre o servidor e o cliente de forma a começar com o processo de encriptação e consequente desencriptação das mensagens enviadas. 
Não foram sentidas dificuldades quanto à implementação dos mecanismos devido a utilização da documentação das bibliotecas cryptography e pycryptodome.

## Resultados e Conclusões
Consideramos que este guião foi importante para aprendermos a manipular diferentes modos das cifras por blocos bem como para compreendermos a dinâmica do cliente e servidor.
Em suma, achamos que atingimos o objetivo pretendido do trabalho.

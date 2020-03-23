# Guião 1

## Contextualização
Primeiramente foi-nos pedido para simular um processo de encriptação e desencriptação de uma mensagem, utilizando as bibliotecas de python ( mais especificamente a **criptography.fernet** ).
Depois teríamos de tentar simular um ataque para verificar se esta cifra era de facto de autenticada e protegida, ou seja, se ela mantém algumas características desejadas como integridade.

## Justificação das opções tomadas
Neste primeiro guião todo o processo foi bastante simples. Primeiro criamos um ficheiro de texto com uma mensagem simples para ser facilmente comparada com o mensagem após todo o processo feito sobre ela. 
Tal como nos foi instruído, tínhamos de usar a biblioteca com a cifra de Fernet. Desta maneira foi só estudar a biblioteca em si. Com isso concluímos que antes de tudo tería de ser gerada uma chave fernet com o método `generate_key()`. Esta chave deverá ser usada tanto no processo de encriptação como no de desencriptação visto que é uma forma de encriptação simétrica.
Depois de termos esta chave criamos um método para encriptar a mensagem. Este método é definido através da nossa `encrypt_file(file,key)` que recebe como argumentos o ficheiro que contém a mensagem e a chave anteriormente gerada. Neste método nós geramos uma cifra através da chave e depois aplicamos o método `encrypt()` que recebe como argumento o conjunto de dados correspondente à mensagem do ficheiro de texto. Escrevemos o resultado desse método num ficheiro novo com o nome de **mensagem.encrypted**.
Quanto ao processo inverso seguimos o mesmo raciocínio da encriptação , mas aplicamos o método `decrypt()` aos dados do ficheiro encriptado e escrevemos o resultado no ficheiro **mensagem.decrypted** . 
Para simular o ataque abrimos o ficheiro que continha a mensagem encriptada e adicionamos texto no fim, e voltamos a desencriptar esse ficheiro para podermos verificar se o ataque tinha sido bem sucedido ou não.

## Resultados e conclusões
Para a primeira parte vemos que o processo de encriptação e desencriptação funciona perfeitamente, sendo a mensagem de texto original igual à mensagem após os processos de encriptar e desencriptar.
Quanto ao ataque vemos quer o ataque falhou. O facto da cifra ser autenticada justifica o facto de apesar da mensagem encriptada ter sido deturpada e alterada, o processo de desencriptação funciona perfeitamente na mesma e o resultado é igual à mensagem original.

## Dificuldades encontradas
Sendo esta uma linguagem de programação nova para todos, foi necessária um pequeno estudo sobre a mesma. Desde a sintaxe à codificação dos métodos houve um período de aprendizagem e adaptação à linguagem , o que retardou um pouco a produção do resultado final. A este período é adicionado outra fase de instrução direcionada à biblioteca usada para este guião.

## Instruções
Para podermos usufruir deste pequeno programa basta introduzir no terminal ` $ python3 Guiao1SemAtaque.py ` para podermos ver o resultado da mensagem encriptada e desencriptada sem esta ter sido adulterada. Para ver o que acontece com o ataque feito basta introduzir ` $ python3 Guiao1ComAtaque.py ` .
Além disto foi criada uma Makefile que nos permite apagar os ficheiros que contém as mensagens depois de aplicadas os processos de encriptação e o inverso.

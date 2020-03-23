# Guião 3

## Contextualização 

Este guião estava dividido em três métodos.Um deles era utilizar o processo de MAC then encrypt. Desta forma, iremos explicar o raciocínio adotado assim como as respetivas conclusões tiradas.

## Justificação das opções tomadas
Para o processo acima referido foi utilizado o método PBKDF2HMAC para gerar uma chave de 64 bytes que foi dividida em duas chaves, em que a primeira será para cifrar a mensagem e a segunda será utilizada para o MAC. Cada uma destas keys terá 32 bytes. 
Para o caso da encriptação foi calculado o MAC sobre o texto limpo e guardado numa tag,mac_msg. Posteriormente encriptou se o resultado anterior usando a cifra ChaCha20. 
Para o caso da desencriptação é desencriptado o ficheiro todo. Depois é calculado o mac do texto desencriptado e comparado com o mac que já se encontrava lá.

## Dificuldades encontradas

Neste método o mais difícil foi perceber como funcionava o processo pois era necessário encriptar não só o mac da mensagem como o texto limpo em si. Outra dificuldade foi perceber como funcionavam as bibliotecas CHACHA20 e HMAC-SHA256 pois foi a primeira vez que nos familiarizamos com as mesmas.

## Instruções
Para se testar é necessário compilar primeiro : $ python3 encript.py para encriptar e só depois: $ python3 decript.py para desencriptar.

## Conclusões
Este processo é melhor do que o processo Encrypt and Mac mas pior do que o Encrypt then MAC. Não permite integridade do texto encriptado ao contrário do segundo método anteriormente referido. É mais vantajoso que o primeiro método visto que não fornece qualquer informação sobre o texto limpo uma vez que se encontra encriptado.

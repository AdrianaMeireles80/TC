# Guião 3 :
## Encrypt then MAC
### Contextualização
Um dos pontos a realizar neste guião era conseguir utilizar o processo de **Encrypt then MAC**.
Desta forma, iremos explicar os processo realizado bem como as decisões tomadas.

### Justificação das opções tomadas
Para isto é necessário percebermos em que se baseia este processo de **Encrypt then MAC**.
Para este processo, utilizamos o método *PBKDF2HMAC* para gerar uma chave de 64 bytes, dividindo de seguida em duas chaves, em que a primeira será para cifrar a mensagem e a segunda será utilizada para o MAC. Cada uma destas keys terá 32 bytes. Ciframos a nossa mensagem usando o CHACHA20 e depois fazemos o MAC.

### Resultados e Conclusões
Concluímos que este método é o mais seguros dos três processos apresentados. O texto encriptado é gerado encriptografando um texto e, em seguida, anexando um MAC do texto criptografado.

### Dificuldades Encontradas
Este processo foi bastante simples. A principal dificuldade foi perceber como iria funcionar o processo de encriptação dado que era diferente de outros. Foi necessário utilizar as bibliotecas CHACHA20 e HMAC-SHA256, das quais foi necessário fazer a pesquisa e familiarizar-nos com a mesma, mas depois disto tornou-se bastante simples.

### Instruções
Para testarmos basta introduzir na linha de comandos: `$ python3 encript.py`.

## Contextualização

Na comunicação entre Servidor/Cliente, foi implementado o protocolo Diffie-Hellman onde foram distribuídas as informações das chaves necessárias para a criação de uma chave em comum (shared key).

## Justificação das Opções tomadas

Foram enviados em separado os números dos parâmetros e da chave pública necessários para a recriação das chaves públicas usadas tanto pelo Servidor como pelo Cliente pois não era possível enviar essa chave pública já criada.

## Instruções
Tal como no guião anterior, é necessário usar os seguintes comandos:

python3 servidor.py - Executa o servidor
python3 cliente.py - Executa um cliente

## Dificuldades Encontradas

As principais dificuldades foram na implementação deste protocolo em python pois a documentação da biblioteca
não disponibiliza muita informação pertinente.
Também foram encontradas dificuldades no envio da informação relativa à chave pública tanto do Cliente como do Servidor.

## Resultados e Conclusões
Concluímos que como são usadas diferentes chaves para cifrar e decifrar, a principal vantagem deste método é a sua segurança, pois não é preciso partilhar a chave privada. Por outro lado, a chave pública usada para cifrar está sujeita a ataques man-in-the-middle pois pode ser intercetada.


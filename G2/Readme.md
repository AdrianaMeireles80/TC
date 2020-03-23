# Guião 2

## Contextualização
Após a realização do guião passado, neste segundo guião foi-nos proposto adicionar uma funcionalidade de protecção dos segredos de acordo com ambas as estratégias apresentadas, nomeadamente, *evitar a necessidade de se armazenar a chave* e armazenar o ficheiro de forma protegida, no que se designa habitualmente por *KeyStore*.

## Justificação das opções tomadas
Para o processo de encriptação e desencriptação utilizamos a ferramenta *PBKDF2HMAC* que permite criar uma Fernet Key segundo um salto e uma password. Isto implica que as duas entidades envolvidas no processo além de precisarem da mesma password, também precisam que o valor do salto corresponda. Isso leva a um aumento de segurança e dificuldade de penetração exterior. O processo de encriptação e decriptação em si, não é alterado face ao guião anterior.

## Dificuldades encontradas
Nesta fase, apesar de já estarmos ambientados à linguagem, a dificuldade encontrada consistiu no uso das bibliotecas pré-definidas, dado que foi algo que teve de ser analisado com tempo e detalhadamente de forma a conseguir utilizá-las facilmente. Após termos ficado familiarizados com as mesmas, o processo realizou-se de forma geral sem muita dificuldade.

## Resultados e Conclusões
Com este guião vimos outro tipo de processo de encriptação. Apesar de ser um pouco mais complexo, podemos facilmente verificar que este é mais seguro e com maior cuidado contra ataques alheios.
Além disso é um processo confiável visto que garante a proteção dos segredos e que mantém os dados na sua integridade.

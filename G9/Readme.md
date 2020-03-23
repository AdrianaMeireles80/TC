# Guião 9

## Contextualização
Para este guião foi-nos proposta a implementação do protocolo Station_to_Station fazendo uso de certificados X509. Utilizamos os guiões 7 e 8 como base para a implementação deste guião 9.

## Justificação das opções tomadas
Este guião veio no seguimento do trabalho realizado no guião 7, sendo as diferenças o acréscimo do envio de certificados e o facto das entidades não saberem previamente as chaves públicas das assinaturas do outro.

Assim começamos todo o processo calculando a **private_key** das assinaturas através do seu certificado e passar o seu certificado para um *bytebuffer* para poder ser enviado diretamente.
Depois, como no guião 7, o cliente começa por enviar ao servidor a sua chave pública da encriptação assimétrica. O Servidor recebe-a, calcula o segredo partilhado, em junção com a sua própria chave privada, e envia ao cliente a sua chave pública, juntamente com a assinatura e o seu certificado. O cliente começa por verificar se o certificado é válido através do método `verify_cert(msg)`, onde a variável `msg` corresponde aos bytes do certificado recebido. Se este for validado, o cliente pega nesse certificado e com o método `get_other_public_key(msg)` consegue adquirir a chave pública de assinatura do servidor. Através dessa chave ele consegue verificar se a assinatura recebida é de facto assinada pelo cliente. Se assim o for, este pega na chave pública recebida do cliente e também pode calcular o segredo partilhado para a cifra assimétrica. Ele envia de volta uma assinatura sobre as duas chaves públicas e o seu certificado. Aqui no lado do servidor o processo é idêntico ao do cliente, onde ele verifica o certificado, depois a assinatura e se estiver tudo correto ele envia uma mensagem ao cliente a dizer que pode começar a enviar mensagens.

Dado isto sabemos que todo o processo de comunicação é seguro.

## Dificuldades encontradas
Houve dificuldade no que toca à comunicação de certificados entre Cliente e Servidor bem como na interpretação da biblioteca utilizada.

## Instruções
Para testar este Guião são necessários 2 comandos.
Abre-se um terminal:
* `python3 servidor.py`
Noutro terminal:
* `python3 cliente.py`

## Conclusões
Concluimos que com este processo, ao garantir a validação de certificados asseguramos a cada um dos intervenientes (Servidor e Cliente) o uso da chave pública correta na verificação de assinaturas.

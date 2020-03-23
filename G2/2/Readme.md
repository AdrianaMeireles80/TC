# 2º Guião

## Parte 2

### Introdução
Nesta parte, durante o processo de encriptação guardamos o salt no ficheiro *salt.Keystore* . Para tal é gerada uma Fernet key para encriptarmos este mesmo salt, sendo ela também guardada num ficheiro : *salt.Keystore*. 
Já no processo de desencriptação, se as passwords coincidirem vai funcionar como esperado.

### Instruções
Para testarmos teremos primeiro de introduzir na linha de comandos `$ python3 encript.py` e depois para desencriptar `$ python3 decript.py`

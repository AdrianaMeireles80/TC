from Crypto.Random import get_random_bytes
from random import randint 

## ---------------- CLASSE DA CIFRA -------------- ##

class Cipher:
    
    # Gera uma chave aleatória
    def keygen(self):
        k = get_random_bytes(16)
        return k
    
    # Cifra com a função identidade
    def enc(self,key,msg):
        return msg
    
    # Decifra com a função identidade
    def dec(self,key,msg):
        return msg

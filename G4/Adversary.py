from Crypto.Random import get_random_bytes
from random import randint

## ---------------- CLASSE DO ADVERSÁRIO -------------- ##

class Adversary_Det:
    
    # Devolve as duas mensagens
    def getMessages(self, enc_oracle):
         return (b"00000000",b"11111111") 
    
    # Recebe uma mensagem encriptada. Vai encriptar a mensagem(b"11111111") e comparar com a recebida
    def guess(self,enc_oracle,c):
        c2 = enc_oracle(b"11111111")
        print("Adversário a testar: "+ str(c2) + "\n     *\n     *\n     *")
        if(c == c2):
            return True
        else:
            return False

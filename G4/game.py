from Crypto.Random import get_random_bytes
from random import randint
import Cipher as cifra 
import Adversary as enemy

## ---------------- CLASSE DO JOGO -------------- ##

def random_bit(): # Função que devolve 0 ou 1 
    return randint(0,1)

def IND_CPA(C,A): #Devolve o valor de verdade da tentaiva de decifrar
    k = C.keygen() # gera a chave aleatória
    enc_oracle = lambda ptxt: C.enc(k,ptxt) 
    m = A.getMessages(enc_oracle) # Obtenho as duas mensagens 
    b = random_bit() # gera um bit aleatório
    c = C.enc(k,m[b]) # cifro uma mensagem, conforme o bit anterior
    print("Cipher a encriptar a mensagem: " + str(m[b])+ "\n")
    
    bx = A.guess(enc_oracle,c) #o adversário tentar adivinhar
    ret = b==bx
    if(ret == True and bx == True):
        print("Adversário descobriu a mensagem: "+ str(m[1]) + "\n")
    elif (ret == True and bx == False):
        print("Adversário descobriu a mensagem: "+ str(m[0]) + "\n")
    return ret

def main():
    C = cifra.Cipher()
    A = enemy.Adversary_Det()
    if(IND_CPA(C,A)):
        print("Cifra Identidade quebrada! O adversário venceu!")

if __name__ == "__main__":
    main()
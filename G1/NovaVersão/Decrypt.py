from cryptography.fernet import Fernet

def decrypte_file(file):
    with open("./key.txt") as f:
        key = f.read()
    cypher = Fernet(key) #Cria a cifra Fernet
    with open(file,'rb') as f: #Abre o ficheiro a ser desencriptado
        decrypted_file = cypher.decrypt(f.read()) #desencripta a mensagem
    ffile = file[:-10] #remove o .encrypted
    with open(ffile + '.decrypted', 'wb') as f: #abre o ficheiro.decrypted
        f.write(decrypted_file) #escreve  a mensagem desencriptada

def main():
    decrypte_file("./mensagem.encrypted") #Desencripta a mensagem


if __name__ == "__main__":
    main()

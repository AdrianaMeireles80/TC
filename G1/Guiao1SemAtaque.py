from cryptography.fernet import Fernet

def encrypt_file(file,key):
    cypher = Fernet(key) #Crio a cifra Fernet segundo a sequência de bytes anteriormente gerada
    with open(file,"rb") as f:
        encrypted_file = cypher.encrypt(f.read()) #Encripta o texto do ficheiro
    ffile= file[:-4] #Remover o ".txt" do nome do ficheiro
    with open(ffile + '.encrypted' , 'wb') as f: #Abre o ficheiro de escrita
        f.write(encrypted_file) #Escreve o texto já encriptado

def decrypte_file(file,key):
    cypher = Fernet(key) #Cria a cifra Fernet
    with open(file,'rb') as f: #Abre o ficheiro a ser desencriptado
        decrypted_file = cypher.decrypt(f.read()) #desencripta a mensagem
    ffile = file[:-10] #remove o .encrypted
    with open(ffile + '.decrypted', 'wb') as f: #abre o ficheiro.decrypted
        f.write(decrypted_file) #escreve  a mensagem desencriptada

def main():
    key = Fernet.generate_key() #Gera a squeência de bytes que corresponde à chave
    encrypt_file("./mensagem.txt",key) #Encripta o texto do ficheiro
    decrypte_file("./mensagem.encrypted",key) #Desencripta a mensagem


if __name__ == "__main__":
    main()

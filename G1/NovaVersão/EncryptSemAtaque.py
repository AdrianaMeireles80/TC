from cryptography.fernet import Fernet

def encrypt_file(file):
    with open("./key.txt","rb") as f:
        key=f.read()
    cypher = Fernet(key) #Crio a cifra Fernet segundo a sequência de bytes anteriormente gerada
    with open(file,"rb") as f:
        encrypted_file = cypher.encrypt(f.read()) #Encripta o texto do ficheiro
    ffile= file[:-4] #Remover o ".txt" do nome do ficheiro
    with open(ffile + '.encrypted' , 'wb') as f: #Abre o ficheiro de escrita
        f.write(encrypted_file) #Escreve o texto já encriptado


def main():
    key = Fernet.generate_key() #Gera a squeência de bytes que corresponde à chave
    with open("./key.txt","wb") as f:
        f.write(key)
    encrypt_file("./mensagem.txt") #Encripta o texto do ficheiro


if __name__ == "__main__":
    main()
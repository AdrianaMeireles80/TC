import base64
import os
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

salt_aux = os.urandom(16)

def passwd(pwd):
    backend = default_backend()
    salt = salt_aux
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key_bytes = kdf.derive(pwd)
    return key_bytes,salt


def encript_file(password):    
    key_bytes,salt = passwd(password)
    key = base64.urlsafe_b64encode(key_bytes)
    k = Fernet(key)
    #3º PASSO:
    with open("./mensagem.txt","rb") as ff:
        encrypted_file = k.encrypt(ff.read())
    with open("mensagem.enc",'wb') as msgfile:
        sz = msgfile.write(encrypted_file)

def decript_file(password):
    key_bytes,salt = passwd(password)
    key = base64.urlsafe_b64encode(key_bytes)
    cypher = Fernet(key)
    #3º PASSO:
    with open("mensagem.enc",'rb') as f: #Abre o ficheiro a ser desencriptado
        decrypted_file = cypher.decrypt(f.read()) #desencripta a mensagem
    with open("mensagem.decrypted", 'wb') as f: #abre o ficheiro.decrypted
        f.write(decrypted_file) #escreve  a mensagem desencriptada

def main():
    print("Password to encript your file:")
    #PEDE A PASSWORD
    passw = getpass.getpass()
    #TRANSFORMA EM BYTES
    pwd = str.encode(passw)
    #encriptação do ficheiro segundo a password
    encript_file(pwd)

    print("Password to decript file:")
    #PEDE A PASSWORD
    passw2 = getpass.getpass()
    #TRANSFORMA EM BYTES
    pwd2 = str.encode(passw2)
    #decriptação do ficheiro segundo a password
    decript_file(pwd2)

if __name__ == "__main__":
    main()
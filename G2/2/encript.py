import base64
import os
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

def passwd(pwd):
    backend = default_backend()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key_bytes = kdf.derive(pwd)
    return key_bytes,salt

def encript(password):
    key_bytes,salt = passwd(password)
    key = base64.urlsafe_b64encode(key_bytes)
    k = Fernet(key)

    #Cria cifra auxiliar para guardar o salt
    salt_key = Fernet.generate_key()
    with open("Key_salt.keystore","wb") as f:
        f.write(salt_key)

    salt_cypher = Fernet(salt_key)
    with open("salt.Keystore","wb") as f:
        f.write(salt_cypher.encrypt(salt)) 

    #encripto a mensagem
    with open("mensagem.txt","rb") as f:
        message_encripted = k.encrypt(f.read())
    
    with open("mensagem.enc","wb") as f:
        f.write(message_encripted)


def main():
    #PEDE A PASSWORD
    passw = getpass.getpass()
    #TRANSFORMA EM BYTES
    pwd = str.encode(passw)
    #encriptação do ficheiro segundo a password
    encript(pwd)

if __name__ == "__main__":
    main()
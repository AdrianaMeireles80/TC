import base64
import os
import getpass
import sys
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

def encrypt(pwd):
    key_bytes, salt = passwd(pwd) 
    password_key = base64.urlsafe_b64encode(key_bytes) #Key for Fernet
    password_cypher = Fernet(password_key) #fernet cypher

    #encrypt message
    with open("mensagem.txt","rb") as plaintext:
        enc_msg = password_cypher.encrypt(plaintext.read())

    #Create a random key to cypher all file
    k = Fernet.generate_key()
    kcypher = Fernet(k)

    #Write random fernet key
    with open("key","wb") as fk:
        fk.write(k)
    
    #Write salt and encrypted message in cryptogram 
    with open("mensagem.enc","wb") as f:
        f.write(kcypher.encrypt(salt + enc_msg))
    
    

def main():
    passw = getpass.getpass() #Asks for a Password
    pwd = str.encode(passw) #Bytes transformed
    encrypt(pwd) #Encript file with password asked

if __name__ == "__main__":
    main()
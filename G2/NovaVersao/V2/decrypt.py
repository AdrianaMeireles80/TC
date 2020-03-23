import base64
import os
import getpass
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def passwd(pwd,salt):
    backend = default_backend()
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=backend
    )
    key_bytes = kdf.derive(pwd)
    return key_bytes


def decrypt(pwd):
    with open("mensagem.enc","rb") as f:
        decripted_file = f.read() #ler ficheiro encriptado
    
    salt = decripted_file[0:16] #salt
    enc_msg = decripted_file[16:]
    key_bytes = passwd(pwd,salt) 
    
    password_key = base64.urlsafe_b64encode(key_bytes) #Key for Fernet
    password_cypher = Fernet(password_key) #fernet cypher
    
    try:
        #fernet random key
        with open("Keystore.keystore","rb") as kf:
            randomkey = password_cypher.decrypt(kf.read())
        cipher = Fernet(randomkey)
        final_msg = cipher.decrypt(enc_msg)
        with open("mensagem.dec","wb") as f:
            f.write(final_msg)
    except InvalidToken:
        print("Wrong password!")


def main():
    passw = getpass.getpass() #Asks for a Password
    pwd = str.encode(passw) #Bytes transformed
    decrypt(pwd) #Encript file with password asked

if __name__ == "__main__":
    main()
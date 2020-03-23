import base64
import os
import getpass
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken

def passwd(pwd,salt):
    backend = default_backend()  
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key_bytes = kdf.derive(pwd)
    return key_bytes

def decrypt(pwd):
    #fernet random key
    with open("key","rb") as kf:
        fk = kf.read()

    kcypher = Fernet(fk)

    with open("mensagem.enc","rb") as f:
        decripted_file = kcypher.decrypt(f.read())

    salt = decripted_file[0:16]
    key_bytes = passwd(pwd,salt)
    
    
    try:
        key = base64.urlsafe_b64encode(key_bytes) #Key for Fernet
        cypher = Fernet(key) #fernet cypher
        dec_msg = decripted_file[16:]
        final_msg = cypher.decrypt(dec_msg)
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
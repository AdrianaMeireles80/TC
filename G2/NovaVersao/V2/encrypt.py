import base64
import os
import getpass
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def passwd(pwd):
    backend = default_backend()
    salt = os.urandom(16)  
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=backend
    )
    key_bytes = kdf.derive(pwd)
    return key_bytes,salt

def encrypt(pwd):
    key_bytes, salt = passwd(pwd) 
    key = base64.urlsafe_b64encode(key_bytes) #Key for Fernet
    password_cypher = Fernet(key) #fernet cypher

    randomkey = Fernet.generate_key()
    randomcypher = Fernet(randomkey)

    # Random key for Fernet
    with open("Keystore.keystore","wb") as f:
        f.write(password_cypher.encrypt(randomkey))

    # encrypt mesage
    with open("mensagem.txt","rb") as plaintext:
        enc_msg = randomcypher.encrypt(plaintext.read())

    final_msg = salt + enc_msg
    #Write encrypted message in cryptogram 
    with open("mensagem.enc","wb") as f:
        f.write(final_msg)


def main():
    passw = getpass.getpass() #Asks for a Password
    pwd = str.encode(passw) #Bytes transformed
    encrypt(pwd) #Encript file with password asked

if __name__ == "__main__":
    main()
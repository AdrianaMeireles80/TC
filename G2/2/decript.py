import base64
import os
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

def passwd(pwd):
    backend = default_backend()
    salt = getSalt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key_bytes = kdf.derive(pwd)
    return key_bytes,salt

def getSalt():
    with open("Key_salt.keystore", "rb") as f:
        key = f.read()
    cypher = Fernet(key)

    with open("salt.Keystore","rb") as f:
        salt = cypher.decrypt(f.read())
    return salt



def decript(pwd):
    key_bytes,salt = passwd(pwd)
    key = base64.urlsafe_b64encode(key_bytes)
    k = Fernet(key)
    with open("mensagem.enc","rb") as f:
        dm = k.decrypt(f.read())
    with open("mensagem.dec","wb") as f:
        f.write(dm)


def main():
    #PEDE A PASSWORD
    passw = getpass.getpass()
    #TRANSFORMA EM BYTES
    pwd = str.encode(passw)
    #encriptação do ficheiro segundo a password
    decript(pwd)

if __name__ == "__main__":
    main()
import base64
import os
import getpass
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import ChaCha20
from Crypto.Hash import HMAC, SHA256
 
def passwd(pwd):
    backend = default_backend()
    salt = os.urandom(16)
    #PBKDF2 derivation function
    kdf = PBKDF2HMAC(
    algorithm = hashes.SHA256(),
    length = 64,
    salt = salt,
    iterations = 100000,
    backend = backend
    )
    #Encrypt password with PBKDF2
    key_bytes = kdf.derive(pwd)
   
    #Return key and salt
    return key_bytes,salt

def mac_then_encript(password):
    key, salt = passwd(password) 

    plaintext =  open("mensagem.txt",'rb') 

    enc_key = key[0:32]
    mac_key = key[32:]

    mac = HMAC.new(mac_key,plaintext.read(),digestmod=SHA256)
    mac_msg = mac.hexdigest().encode()

    cypher = ChaCha20.new(key=enc_key)

    cypher_nonce = cypher.nonce


    with open("mensagem.txt","rb") as f:
        enc_msg = cypher.nonce + cypher.encrypt(mac_msg+f.read())

    with open("mensagem.enc","wb") as final_msg:
        final_msg.write(salt + enc_msg)

def main():
    #PEDE A PASSWORD
    passw = getpass.getpass()
    #TRANSFORMA EM BYTES
    pwd = str.encode(passw)
    #encriptação do ficheiro segundo a password
    mac_then_encript(pwd)

if __name__ == "__main__":
    main()
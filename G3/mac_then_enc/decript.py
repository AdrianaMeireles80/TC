import base64
import os
import getpass
import sys
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import ChaCha20
from Crypto.Hash import HMAC, SHA256

def passwd(pwd):
    backend = default_backend()
    
    with open("mensagem.enc","rb") as f:
        salt = f.read(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key_bytes = kdf.derive(pwd)
    #ENCRIPT KEY
    enc_key = key_bytes[0:32]
    #MAC KEY
    mac_key = key_bytes[32:]
    return enc_key, mac_key

def verify_mac(pwd):
    enc_key, mac_key = passwd(pwd)
    with open("mensagem.txt","rb") as f:
        h = HMAC.new(mac_key,f.read(),digestmod=SHA256)
    #h.hexverify(cleantext)

def decript(pwd):
    enc_key, mac_key = passwd(pwd)
    
    with open("mensagem.enc","rb") as f:
        f.seek(16) #skip salt
        mac_tag=f.read(64) #ler o mac
        enc_msg_nonce= f.read(8) #ler a cifra
        enc_msg = f.read() # ler texto encriptado
    
    cypher = ChaCha20.new(key=enc_key,nonce = enc_msg_nonce)
    
    try:
        cleantext=cypher.decrypt(enc_msg)
        with open("mensagem.dec","wb") as f:
            f.write(cleantext)
    except ValueError:
        print("Messagem compromised")

def main():
    #PEDE A PASSWORD
    passw = getpass.getpass()
    #TRANSFORMA EM BYTES
    pwd = str.encode(passw)
    #encriptação do ficheiro segundo a password
    decript(pwd)

if __name__ == "__main__":
    main()

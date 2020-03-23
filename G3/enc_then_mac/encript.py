import base64
import os
import getpass
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from Crypto.Cipher import ChaCha20
from Crypto.Hash import HMAC, SHA256

def passwd(pwd):
    backend = default_backend()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key_bytes = kdf.derive(pwd)
    return key_bytes,salt

def encript_then_mac(pwd):
    key, salt = passwd(pwd)
    plaintext = open("mensagem.txt","rb")

    enc_key = key[0:32] # Encript key
    mac_key = key[32:] # MAC key
    
    cypher = ChaCha20.new(key=enc_key) #CHACHA20 cypher
    #cypher_nonce = cypher.nonce ## CHACHA20 cypher nonce
    
    #Encript plain text with CHACHA20 cypher
    enc_msg = cypher.nonce + cypher.encrypt(plaintext.read())

    #MAC of cryptogram
    mac = HMAC.new(mac_key,enc_msg,digestmod=SHA256)
    mac_msg = mac.hexdigest().encode()
    
    with open("mensagem.enc","wb") as f:
        f.write( salt + mac_msg + enc_msg )

def main():
    passw = getpass.getpass() #Asks for a Password
    pwd = str.encode(passw) #Bytes transformed
    encript_then_mac(pwd) #Encript file with password asked

if __name__ == "__main__":
    main()

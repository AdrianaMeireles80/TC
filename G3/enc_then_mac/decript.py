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
    
    key_enc = key_bytes[0:32]
    key_mac = key_bytes[32:]

    return key_enc,key_mac

def decript(pwd):
    key_enc,key_mac = passwd(pwd)

     # Take usefull info in cryptogram : plain text's MAC,cypher's nonce and encrypted text
    with open("mensagem.enc","rb") as f:
        f.seek(16) # Skip the salt
        mac_tag=f.read(64) # Read plain text MAC
        enc_msg_nonce= f.read(8) # Read cypher's nonce
        enc_msg = f.read()  # Read encripted text

    msg_to_mac = enc_msg_nonce + enc_msg
 
    h = HMAC.new(key_mac,msg_to_mac,digestmod=SHA256)

    try:
        h.hexverify(mac_tag)
        cypher = ChaCha20.new(key=key_enc,nonce=enc_msg_nonce)
        msg_dec = cypher.decrypt(enc_msg)

        with open("mensagem.dec","wb") as f:
            f.write(msg_dec)

    except ValueError:
        print("Message compromised!")

def main():
    passw = getpass.getpass() #Asks for a Password
    pwd = str.encode(passw) #Bytes transformed
    decript(pwd) #Encript file with password asked

if __name__ == "__main__":
    main()
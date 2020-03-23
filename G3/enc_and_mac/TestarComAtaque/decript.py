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
    
    # Read Salt in cryptogram
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
   
    enc_key = key_bytes[0:32] # ENCRIPT KEY
    mac_key = key_bytes[32:] # MAC KEY
    return enc_key, mac_key


def decript(pwd):
    enc_key, mac_key = passwd(pwd)
    
    # Take usefull info in cryptogram : plain text's MAC,cypher's nonce and encrypted text
    with open("mensagem.enc","rb") as f:
        f.seek(16) # Skip the salt
        mac_tag=f.read(64) # Read plain text MAC
        enc_msg_nonce= f.read(8) # Read cypher's nonce
        enc_msg = f.read()  # Read encripted text
    
    cypher = ChaCha20.new(key=enc_key,nonce = enc_msg_nonce) # Creates cypher
    
    cleantext=cypher.decrypt(enc_msg) #decript message
    
    try:        
        #mac of decripted text
        mac = HMAC.new(mac_key,cleantext,digestmod=SHA256) 
        #compare mac of decripted text with mac tag of plain text
        mac.hexverify(mac_tag)
        
        # Writing decripted message
        with open("mensagem.dec","wb") as f:
            f.write(cleantext)
    except ValueError:
        print("If you put the correct password, you message is compromised!")
    
    

def main():
    passw = getpass.getpass() #Asks for a Password
    pwd = str.encode(passw) #Bytes transformed
    decript(pwd) #trys to decript with password asked

if __name__ == "__main__":
    main()
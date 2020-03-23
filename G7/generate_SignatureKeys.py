#/usr/bin/python3
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def generate_signature_keys():
    client_private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend()) #Gero a private key
    client_pem = client_private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())
    with open("ClientPrivateSignatureKey.pem","wb") as f:
        f.write(client_pem)
    
    client_public_key = client_private_key.public_key()
    client_public_pem = client_public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.PKCS1)
    with open("ClientPublicSignatureKey.pem","wb") as f:
        f.write(client_public_pem)
    
    server_private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())#Gero a private key
    server_pem = server_private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())
    with open("ServerPrivateSignatureKey.pem","wb") as f:
        f.write(server_pem)
    
    server_public_key = server_private_key.public_key()
    server_public_pem = server_public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.PKCS1)
    with open("ServerPublicSignatureKey.pem","wb") as f:
        f.write(server_public_pem)

generate_signature_keys()
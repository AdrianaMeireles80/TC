# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
#/usr/bin/python3
import asyncio
import socket
import os
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from OpenSSL import crypto
from cryptography import x509

conn_port = 8888
max_msg_size = 9999
G = 44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675
P = 99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583
dh_parameters = dh.DHParameterNumbers(G,P, q = None).parameters(default_backend())


class Client:


    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0
        self.client_private_key = dh_parameters.generate_private_key() #chave privada do cliente
        self.client_public_key = self.client_private_key.public_key() #chave publica do cliente
        self.server_public_key = None
        self.shared_key = None
        self.cipher_key = None
        self.cipher_salt = None
        self.signature_private_key = None
        self.server_signature_public_key = None
        self.cert = None

    def get_own_private_key(self):
        passwd=b"1234" #Password do 
        #ler pkcs12
        p12 = crypto.load_pkcs12(open("./files/Cliente1.p12", 'rb').read(), passwd)
        skC =crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
        private_keyC = serialization.load_pem_private_key(
            skC,
            password=None,
            backend=default_backend()
        )
        self.signature_private_key = private_keyC
    
    def self_certificate(self):
        passwd = b"1234"
        c_p12 = crypto.load_pkcs12(open("./files/Cliente1.p12",'rb').read(),passwd)
        certC = crypto.dump_certificate(crypto.FILETYPE_PEM,c_p12.get_certificate())
        self.cert = certC

    def get_other_public_key(self,msg):
        cert = x509.load_pem_x509_certificate(msg,default_backend()) #Tenho o certificado
        #print(cert)
        publickey = cert.public_key()
        #print(publickey)
        self.server_signature_public_key = publickey

    def verify_cert(self,msg):
        with open('./files/CA.cer', 'rb') as cert_file:
            trust_cert_pem = cert_file.read()
        
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, msg) #Tenho o certificado

        # Create and fill a X509Sore with trusted certs
        store = crypto.X509Store()
        trusted_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, trust_cert_pem)
        store.add_cert(trusted_cert)

        store_ctx = crypto.X509StoreContext(store, cert)
        # Returns None if certificate can be validated
        result = store_ctx.verify_certificate()
        if result is None:
            return True
        else:
            return False


    #-------------------------------- Assinaturas ----------------------------------#
    def signature_sign(self,message):
    	signature =self.signature_private_key.sign(
            message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    	return signature

    def signature_verify(self, message,sig):
        self.server_signature_public_key.verify(
            sig,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def passwd(self,key):
        backend = default_backend()
        salt = os.urandom(16)  
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=salt,
            info=b'TC1920-G4',
            backend=backend
        ).derive(key)
        return kdf,salt
    
    
    def encription(self,msg):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.cipher_key), modes.GCM(iv), default_backend())
        encryptor = cipher.encryptor()
        encripted_text = encryptor.update(msg) + encryptor.finalize()
        new_msg2 = self.cipher_salt + iv + encryptor.tag + encripted_text
        return new_msg2

    def decription(self,msg_text,salt,iv,tag):
        backend = default_backend()
        salt = salt 
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=salt,
            info=b'TC1920-G4',
            backend=backend
        ).derive(self.shared_key)

        cipher = Cipher(algorithms.AES(kdf), modes.GCM(iv,tag), default_backend())
        decryptor = cipher.decryptor()
        msg = decryptor.update(msg_text) + decryptor.finalize()
        return msg


    #Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR. Retorna a mensagem a transmitir como resposta
    # (`None` para finalizar ligação)
    def process(self, msg=b""):
        self.get_own_private_key()
        self.self_certificate()
        self.msg_cnt +=1

        if(self.msg_cnt == 1): #Enviar a sua Public Key ao servidor
            client_public_key_bytes = self.client_public_key.public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            
            print("\n---Enviando a minha chave pública!---\n")
            
            return client_public_key_bytes #retorna a chave publica do cliente em bytes

        elif (self.msg_cnt == 2): #Receber a public key do servidor
            
            try:
                sig = msg[0:256]
                certs = msg[256:1541] #certificado
                msg1 = msg[1541:]
                
                self.verify_cert(certs)

                self.get_other_public_key(certs)
                
                try:
                    self.signature_verify(msg1,sig)
                
                    self.server_public_key = serialization.load_der_public_key(data=msg1, backend=default_backend())
                    print("\n---Recebi a chave pública do servidor!---\n")

                    self.shared_key = self.client_private_key.exchange(self.server_public_key) #chave publica
                    key, salt = self.passwd(self.shared_key)
                    self.cipher_key = key
                    self.cipher_salt = salt

                    new_msg = self.client_public_key.public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)
                    new_msg+= self.server_public_key.public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)
                

                    sig = self.signature_sign(new_msg)
                    #print(len(sig))
                    new_msg3 = sig + self.cert + new_msg
                    #print(len(self.cert))
                    return new_msg3 if len(new_msg) > 0 else None

                except(InvalidSignature):
                    print("Assinatura inválida!")
            except(ValueError):
                print("Certificado errado!")
        
        elif (self.msg_cnt >=3):
            if msg:
                salt = msg[0:16]
                iv = msg[16:32]
                tag = msg[32:48]
                msg_text = msg[48:]
                try:
                    msg = self.decription(msg_text,salt,iv,tag)
                    print(' [ Received (%d): %r ]\n' % (self.msg_cnt, msg.decode()))
                except (ValueError):
                    print("!!!ERRO!!! Criptograma corrompido!")

            print('Input message to send (empty to finish)')
            new_msg = input().encode()
            new_msg2 = self.encription(new_msg)

            return new_msg2 if len(new_msg) > 0 else None



#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


@asyncio.coroutine
def tcp_echo_client(loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()

    reader, writer = yield from asyncio.open_connection('127.0.0.1',
                                                        conn_port, loop=loop)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    msg = client.process()
    while msg:
        writer.write(msg)
        msg = yield from reader.read(max_msg_size)
        if msg :
            msg = client.process(msg)
        else:
            break
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())

run_client()
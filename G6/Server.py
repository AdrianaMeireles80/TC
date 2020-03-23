# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
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
from Crypto.Cipher import AES
conn_cnt = 0
conn_port = 8888
max_msg_size = 9999
G = 44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675
P = 99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583
dh_parameters = dh.DHParameterNumbers(G,P, q = None).parameters(default_backend())



class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.server_private_key = None
        self.server_public_key = None
        self.client_public_key = None
        self.derived_key = b""
        self.cipher_key = None
        self.hmac_key = None
    
    #Processa uma mensagem (`bytestring`) enviada pelo CLIENTE. Retorna a mensagem a transmitir como resposta 
    # (`None` para finalizar ligação)
    def process(self, msg):
        self.msg_cnt += 1
        
        if(self.msg_cnt == 1): #Enviar ao cliente a minha chave pública
            self.server_private_key = dh_parameters.generate_private_key() #server chave privada
            self.server_public_key = self.server_private_key.public_key() #server chave publica
            server_public_key_bytes = self.server_public_key.public_bytes(encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            self.client_public_key = serialization.load_der_public_key(data=msg, backend=default_backend())
            print("Recebida a chave pública do cliente!")

            shared_key = self.server_private_key.exchange(self.client_public_key)
            
            self.derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'TC1920-G4',
                backend=default_backend()
            ).derive(shared_key)

            self.hmac_key=self.derived_key[16:]
            self.cipher_key=self.derived_key[:16]

            print("Enviando a minha chave pública!")
            return server_public_key_bytes # send server public key to the client 
       
        elif(self.msg_cnt >= 2):
            if msg: 
                criptoIV, tag = msg[:-32], msg[-32:]
                iv, cripto = criptoIV[:16], criptoIV[16:]


                h = hmac.HMAC(self.hmac_key, hashes.SHA256(), default_backend())
                h.update(cripto)
                
                try:
                    h.verify(tag)
                    cipher = Cipher(algorithms.AES(self.cipher_key), modes.CTR(iv), default_backend())
                    decryptor = cipher.decryptor()
                    msg = decryptor.update(cripto) + decryptor.finalize()

                    print('Received (%d): %r' % (self.msg_cnt, msg.decode()))
                except (InvalidSignature):
                    print("Oops!  Não se verificou a integridade do criptograma.")


            print('%d : %r' % (self.id, msg.decode()))
            new_msg = msg.decode().upper().encode()
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.cipher_key), modes.CTR(iv), default_backend())
            encryptor = cipher.encryptor()
            ct = encryptor.update(new_msg) + encryptor.finalize()
            # mac
            h = hmac.HMAC(self.hmac_key, hashes.SHA256(), default_backend())
            h.update(ct)
            tag = h.finalize()
            new_msg2 = (iv+ct)+tag

            return new_msg2 if len(new_msg) > 0 else None

        #------------------------------------------------#        
        txt = msg.decode()
        print('%d : %r' % (self.id,txt))
        new_msg = txt.upper().encode()
        
        return new_msg if len(new_msg)>0 else None
    


#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


@asyncio.coroutine
def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)
    data = yield from reader.read(max_msg_size)
    while True:
        if not data: continue
        if data[:1]==b'\n': break
        data = srvwrk.process(data)
        if not data: break
        writer.write(data)
        yield from writer.drain()
        data = yield from reader.read(max_msg_size)
    print("[%d]" % srvwrk.id)
    writer.close()


def run_server():
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port, loop=loop)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')

run_server()
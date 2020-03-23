# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import os
import asyncio
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

conn_cnt = 0
conn_port = 8888
max_msg_size = 9999

class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0


    
    def decription(self,key,iv,tag,msg):
        cipherkey = key[0:16]
        hmackey = key[16:32]

        h = hmac.HMAC(hmackey, hashes.SHA256(), default_backend())
        h.update(msg)
                
        try:
            h.verify(tag)
            cipher = Cipher(algorithms.AES(cipherkey), modes.CTR(iv), default_backend())
            decryptor = cipher.decryptor()
            new_msg = decryptor.update(msg) + decryptor.finalize()
            print(new_msg)
            return new_msg
        except (InvalidSignature):
             print("Oops!  Não se verificou a integridade do criptograma.")
             new_msg = b"Oops! Nao se verificou a integridade do criptograma"
             return new_msg  



    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        #---------------DECRIPTED TEXT-------------------#
        salt=msg[0:16]
        iv=msg[16:32]
        tag = msg[32:64]
        ciphertext=msg[64:]
        # Get key from PBKDF2
        key = passwd(salt)
        
        try:
            plaintext = self.decription(key,iv,tag,ciphertext)    
        
            print('%d : %r' % (self.id,plaintext.decode()))
        
        except InvalidSignature:
            print('%d : Message compromised!' % (self.id)) 
            aux = "Message compromised, please send again"
            plaintext = aux.encode() 
       #----------------------------------#
        return plaintext if len(plaintext)>0 else None





#------------------------PASSWORD TO KEYSTREAM-------------------------------------#

def passwd(osalt):
    backend = default_backend()
    salt = osalt
    # PBKDF2 derivation function
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
    )
    # pass-phrase
    password = b"1920-TC-G4"
    # Encrypt password with PBKDF2
    key = kdf.derive(password)
    # Return key and salt
    return key


#----------------------------------------------------------------------------------#


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
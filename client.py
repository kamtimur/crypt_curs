import asyncio
import asn1tools
import random
import string
from eleptic import *
from crypt import *
from pygost.gost3410 import CURVE_PARAMS #p, q, a, b, x, y
from pygost.gost3412 import *
from pygost.utils import *
from random import randrange
from pygost.utils import *
from pygost.gost34112012 import GOST34112012 as GostHash
import sys

message = 'Hello World!'
cmd_scheme = asn1tools.compile_files('schemes/cmd_scheme.asn')
challenge_scheme = asn1tools.compile_files('schemes/challenge_scheme.asn')
gost_sign_file = asn1tools.compile_files('schemes/gost_sign.asn')
pub_key_scheme = asn1tools.compile_files('schemes/public_key_scheme.asn')
session_key_scheme = asn1tools.compile_files('schemes/session_scheme.asn')
cert_scheme = asn1tools.compile_files('schemes/cert_scheme.asn')
priv_key_scheme = asn1tools.compile_files('schemes/private_key_scheme.asn')

#Сессия хранит ключи для каждого сокета
#Открытый ключ ввиде структуры асн1
class Session:
    def __init__(self,sock, pubkey, session_key):
        self.sock = sock
        self.pubkey = pubkey
        self.session_key = session_key
        self.verified = False


def GenerateCmd(cmd_string, data):
    all_data = bytearray(cmd_string.encode()+bytearray(data))
    sign = GenSign(curve, all_data, d, Q)
    message = cmd_scheme.encode('CmdFile',
                                {
                                    'command': cmd_string,
                                    'data': data,
                                    'sign': sign
                                })
    return message

def HelloResponse(message_array, reader, writer):

    #получение открытого ключа
    cert_data = message_array['data']
    cert_array = cert_scheme.decode('Cert', cert_data)
    pub_key_data = cert_array['pub']
    sign_data = cert_array['sign']

    validate = AuthSign(curve, bytearray(pub_key_data),sign_data,pub_key_CA)
    # валидировать открытый ключ
    #validate = True
    #создание сессии
    if validate == True:
        sock = writer.transport.get_extra_info('socket')
        session = Session(sock,pub_key_data,None)
        session_list.append(session)
        # tmp = next((x for x in session_list if x.sock == sock), None)
        #отправка челленджа
        challenge_data = challenge_scheme.encode('Challenge',
                                                 {
                                                     'challenge': challenge
                                                 })
        message = GenerateCmd('challenge', challenge_data)
        writer.write(message)
        return
    cmd_message = GenerateCmd('invalid',bytearray(''.encode()), bytearray(''.encode()))
    writer.write(cmd_message)

def HelloRequest(reader, writer):

    #отправить сертификат
    #подписать
    cmd_message = GenerateCmd('hello',cert_data)
    writer.write(cmd_message)

def ChallengeResponse(message_array, reader, writer):
    challenge_asn1 = message_array['data']
    challenge_array = challenge_scheme.decode('Challenge',challenge_asn1)
    challenge = challenge_array['challenge']
    print('challenge arrived',challenge)
    # подписать challenge и отправить его
    sign = GenSign(curve, challenge.encode(),d,Q)

    message = GenerateCmd('challenge_response',sign)
    writer.write(message)
    HelloRequest(reader, writer)

def VerifyChallenge(message_array, reader, writer):
    print('verifyChallenge')
    #проверить challenge и отправить разрешение и сессионный ключ
    sock = writer.transport.get_extra_info('socket')
    tmp = next((x for x in session_list if x.sock == sock), None)
    # получение открытого ключа
    public_key_array = pub_key_scheme.decode('PubKey', tmp.pubkey)
    Q = (public_key_array['keyset']['key']['keydata']['qx'], public_key_array['keyset']['key']['keydata']['qy'])

    sign_data = message_array['data']

    verified = AuthSign(curve, bytearray(challenge, 'utf-8'), sign_data,Q)
    if verified == True:
        # сгенерировать сессионный ключ,получить окрытый ключ из сессии, зашифровать его открытым ключом, взять хэш подписать и отправить
        # генерация сессионного ключа
        enhex = lambda x: ''.join(hex(ord(i))[2:] for i in x)  # записываем шестнадцатиричное представление ключа

        abc = 'abcdefghijklmnopqrstuvwxyz'
        randomKey = lambda: enhex(
            ''.join(random.choice(abc) for i in range(32)))  # генерируем случайную последвательность символов

        key = hexdec(randomKey())
        keystr = key.decode("utf-8")
        # запись его в сессию
        tmp.session_key = key
        # print(tmp.sock,tmp.pubkey, tmp.session_key)
        # print(key)

        #шифрование сессионного ключа
        P, c = EncryptGostOpen(keystr, curve, Q)

        session_key_data = session_key_scheme.encode('SessionKey',
                                                 {
                                                     'px': P[0],
                                                     'py': P[1],
                                                     'c': c
                                                 })

        # gost = GOST3412Kuznechik(tmp.session_key)
        print('session_key',tmp.session_key)

        #отправка ключа
        message = GenerateCmd('allow_con',session_key_data)
    else:
        message = GenerateCmd('invalid', bytearray(''.encode()))
    writer.write(message)

def EstablishSessionKey(message_array, reader, writer):

    session_key_asn1 = message_array['data']
    session_key_array = session_key_scheme.decode('SessionKey',session_key_asn1)
    P = (session_key_array['px'], session_key_array['py'])
    c = session_key_array['c']
    dec = DecryptGostOpen(curve, P, c, d)
    sock = writer.transport.get_extra_info('socket')
    tmp = next((x for x in session_list if x.sock == sock), None)
    deckey = decode_string(dec, 32)
    tmp.session_key = deckey.encode('utf-8')
    message = GenerateCmd('ses_est', bytearray(''.encode()))
    writer.write(message)

def TransmitData(message_array, reader, writer):
    sock = writer.transport.get_extra_info('socket')
    tmp = next((x for x in session_list if x.sock == sock), None)
    if(tmp.session_key == None):
        message = GenerateCmd('invalid', bytearray(''.encode()))
        writer.write(message)
        return
    data = RandomString(256)
    print('key',tmp.session_key)
    ses_key = (tmp.session_key)
    print('key',ses_key)
    gost = GOST3412Kuznechik(ses_key)
    enc_data = EncryptGostSym(data,gost)
    dec_data = DecryptGostSym(enc_data, gost)
    print('source data      ',data)
    print('encrypted data   ', enc_data)
    message = GenerateCmd('data', bytearray(enc_data))
    writer.write(message)

def ShowData(message_array, reader, writer):
    sock = writer.transport.get_extra_info('socket')
    tmp = next((x for x in session_list if x.sock == sock), None)
    if(tmp.session_key == None):
        message = GenerateCmd('invalid', bytearray(''.encode()))
        writer.write(message)
        return
    data = message_array['data']
    print('source data      ',data)

    ses_key = tmp.session_key
    gost = GOST3412Kuznechik(ses_key)
    dec_data = DecryptGostSym(data, gost)

    print('decrypted data   ', dec_data)
    # message = GenerateCmd('get_data', bytearray(''.encode()))
    # writer.write(message)
    # return

def GetData(message_array, reader, writer):
    message = GenerateCmd('get_data', bytearray(''.encode()))
    writer.write(message)

def ProcessInMes(message,reader, writer):
    message_array = cmd_scheme.decode('CmdFile', message)

    #проверить подпись, только после этого выполнять
    cmd = message_array['command']
    if cmd == 'hello':
        HelloResponse(message_array,reader, writer)
        return True
    if cmd == 'challenge':
        ChallengeResponse(message_array, reader, writer)
        return True
    if cmd == 'challenge_response':
        VerifyChallenge(message_array, reader, writer)
        return True
    if cmd == 'allow_con':
        EstablishSessionKey(message_array, reader, writer)
        return True
    if cmd == 'get_data':
        TransmitData(message_array, reader, writer)
        return True
    if cmd == 'ses_est':
        GetData(message_array, reader, writer)
        return True
    if cmd == 'data':
        ShowData(message_array, reader, writer)
        return True
    print('command invalid', cmd)
    return False


async def listener(reader, writer):

    while True:
        response = (await reader.read(8192))
        ProcessInMes(response,reader, writer)


async def connect(port, loop):
    reader, writer = await asyncio.open_connection('localhost', port, loop=loop)

    # print(writer.transport.get_extra_info('socket'))
    sock = writer.transport.get_extra_info('socket')
    session = Session(sock,None,None)
    session_list.append(session)


    HelloRequest(reader, writer)
    while True:
        response = (await reader.read(8192))
        ProcessInMes(response,reader, writer)




client_name = 'client1'
#gen keys
curve_param = CURVE_PARAMS["GostR3410_2012_TC26_ParamSetA"]

curve = EllipticCurve(
    int.from_bytes(curve_param[0], "big"),
    int.from_bytes(curve_param[2], "big"),
    int.from_bytes(curve_param[3], "big"),
    (
        int.from_bytes(curve_param[4], "big"),
        int.from_bytes(curve_param[5], "big")
    ),
    int.from_bytes(curve_param[1], "big")
)

#получить сертификат, ключи
#получить открытый ключ УЦ
#добавить отправку файлов
#добавить проверку сертификатов
#добавить подпись и проверку сообщений
# получение закрытого ключа
priv_key_file = open(client_name+'/'+'cl.priv', "rb")
priv_key_data = priv_key_file.read()
priv_key_array = priv_key_scheme.decode('PrivKey', priv_key_data)
priv_key = priv_key_array['keyset']['key']['keydata']['d']
# получение открытого ключа
pub_key_file = open(client_name+'/'+'cl.pub', "rb")
pub_key_data = pub_key_file.read()
pub_key_array = pub_key_scheme.decode('PubKey', pub_key_data)
pub_key = (pub_key_array['keyset']['key']['keydata']['qx'], pub_key_array['keyset']['key']['keydata']['qy'])
# получение открытого ключа УЦ

cert_file = open(client_name+'/'+'cl.crt', "rb")
cert_data = cert_file.read()

cert_array = cert_scheme.decode('Cert', cert_data)
pub_key_CA_data = cert_array['capub']
pub_key_CA_array = pub_key_scheme.decode('PubKey', pub_key_CA_data)
pub_key_CA = (pub_key_CA_array['keyset']['key']['keydata']['qx'], pub_key_CA_array['keyset']['key']['keydata']['qy'])

print(pub_key_CA)
sign_data = cert_array['sign']
AuthSign(curve, bytearray(pub_key_data),sign_data,pub_key_CA)


d = priv_key
Q = pub_key


session_list=[]
challenge = RandomString(10)

loop = asyncio.get_event_loop()
port = 11111
loop.create_task(asyncio.start_server(listener, 'localhost', port))
loop.create_task(connect(11111, loop))
#loop.create_task(connect(33333, loop))
loop.run_forever()


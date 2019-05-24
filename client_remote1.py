import asyncio
import asn1tools
import random
import string
from eleptic import *
from pygost.gost3410 import CURVE_PARAMS #p, q, a, b, x, y
from pygost.gost3412 import *
from pygost.utils import *
from random import randrange
from pygost.utils import *
import random
from pygost.gost34112012 import GOST34112012 as GostHash
import sys

message = 'Hello World!'
cmd_scheme = asn1tools.compile_files('schemes/cmd_scheme.asn')
challenge_scheme = asn1tools.compile_files('schemes/challenge_scheme.asn')
gost_sign_file = asn1tools.compile_files('schemes/gost_sign.asn')
pub_key_scheme = asn1tools.compile_files('schemes/public_key_scheme.asn')
session_key_scheme = asn1tools.compile_files('schemes/session_scheme.asn')

#Сессия хранит ключи для каждого сокета
#Открытый ключ ввиде структуры асн1
class Session:
    def __init__(self,sock, pubkey, session_key):
        self.sock = sock
        self.pubkey = pubkey
        self.session_key = session_key

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

d = randrange(1, curve.q)
Q = curve.mult(d, curve.P)




def RandomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

def decode_string(res, length):
    vect = []
    for i in range(0, length):
        vect.append(chr(res % 256))
        res = res // 256
    return "".join(reversed(vect))

def EncryptGostOpen(chunk, curv, O):
	num = 0
	for i in chunk:
		num *= 256
		num += ord(i)
	k = randrange(1, curv.p-1)
	pk = curv.mult(k, curv.P)
	qk = curv.mult(k, O)
	l = (num*qk[0])%curv.p
	return pk,l

def DecryptGostOpen(curv, O, l):
    D = curve.mult(d, O)
    t = l*(invert(D[0],curv.p))%curv.p
    return t

def GenSign(message):
    hash_message = GostHash(message.encode()).digest()
    e = int.from_bytes(hash_message, "big", signed=False) % curve.q

    r = 0
    s = 0
    while r == 0 or s == 0:
        k = random.randrange(1, curve.q)
        C = curve.mult(k, curve.P)
        r = C[0] % curve.q
        s = (r*d + k*e) % curve.q


    sign = gost_sign_file.encode('GostSignFile', dict(keyset=
    {
        'key': dict
            (
            algid=b'\x80\x06\x07\x00',
            test='gostSignKey',
            keydata=dict
            (
                qx = Q[0],
                qy = Q[1]
            ),
            param=dict
                (
                fieldparam=dict
                (
                    prime=curve.p
                ),
                curveparam=dict
                    (
                    a=curve.a,
                    b=curve.b
                ),
                genparam=dict
                    (
                    px=curve.P[0],
                    py=curve.P[1]
                ),
                q=curve.q
            ),
            ciphertext=dict
            (
                r=r,
                s=s
            )
        )
    }, last={}))
    print("sign generated")
    return sign

def AuthSign(message, sign_data, Q):
    sign_str = gost_sign_file.decode('GostSignFile', sign_data)
    r = sign_str['keyset']['key']['ciphertext']['r']
    s = sign_str['keyset']['key']['ciphertext']['s']

    if r > curve.q or s > curve.q:
        return False
    hash = GostHash(message.encode()).digest()
    e = int.from_bytes(hash, "big", signed=False) % curve.q
    if e == 0:
        e = 1


    v = invert(e, curve.q)
    z1 = (s*v) % curve.q
    z2 = (-r*v) % curve.q

    C = curve.add(curve.mult(z1, curve.P), curve.mult(z2, Q))

    if  C[0] % curve.q == r:
        print("sign true")
        return True
    else:
        print("sign false")
        return False

def GenerateCmd(cmd_string, data):
    message = cmd_scheme.encode('CmdFile',
                                {
                                    'command': cmd_string,
                                    'data': data
                                })
    return message

def EncryptGostSym(text, gost):
    if isinstance(text, str):
        text = text.encode()
    ans = b''
    for i in range(0, len(text), 16):
        st = text[i:i + 16]
        if len(st) < 16:
            st = st + b' ' * (16 - len(st))
        ans += gost.encrypt(st)
    return ans

def DecryptGostSym(encText, gost):
    ans = b''
    for i in range(0, len(encText), 16):
        st = encText[i:i + 16]
        ans += gost.decrypt(st)
    return ans.rstrip()

def HelloResponse(message_array, reader, writer):

    #получение открытого ключа
    pubkey_asn1 = message_array['data']
    # валидировать открытый ключ
    validate = True
    #создание сессии
    sock = writer.transport.get_extra_info('socket')
    session = Session(sock,pubkey_asn1,None)
    session_list.append(session)
    tmp = next((x for x in session_list if x.sock == sock), None)
    # print(tmp.pubkey)
    #отправка челленджа
    ChallengeRequest(reader, writer)


def HelloRequest(reader, writer):

    #отправить открытый ключ
    #послать свое hello
    pub_key_data = pub_key_scheme.encode('PubKey', dict(keyset=
    {
        'key': dict
            (
            algid=b'\x80\x06\x07\x00',
            test='PubKey',
            keydata=dict
            (
                qx = Q[0],
                qy = Q[1]
            ),
            param=dict
                (
                fieldparam=dict
                (
                    prime=curve.p
                ),
                curveparam=dict
                    (
                    a=curve.a,
                    b=curve.b
                ),
                genparam=dict
                    (
                    px=curve.P[0],
                    py=curve.P[1]
                ),
                q=curve.q
            ),
        )
    }, last={}))
    cmd_message = GenerateCmd('hello',pub_key_data)
    writer.write(cmd_message)

def ChallengeResponse(message_array, reader, writer):
    challenge_asn1 = message_array['data']
    challenge_array = challenge_scheme.decode('Challenge',challenge_asn1)
    challenge = challenge_array['challenge']
    print('challenge arrived',challenge)
    # подписать challenge и отправить его
    sign = GenSign(challenge)

    message = GenerateCmd('challenge_response',sign)
    writer.write(message)


def ChallengeRequest(reader, writer):
    challenge_data = challenge_scheme.encode('Challenge',
                                {
                                    'challenge': challenge
                                })
    message = GenerateCmd('challenge',challenge_data)
    writer.write(message)


def VerifyChallenge(message_array, reader, writer):
    print('verifyChallenge')
    #проверить challenge и отправить разрешение и сессионный ключ
    sock = writer.transport.get_extra_info('socket')
    tmp = next((x for x in session_list if x.sock == sock), None)
    # получение открытого ключа
    public_key_array = pub_key_scheme.decode('PubKey', tmp.pubkey)
    Q = (public_key_array['keyset']['key']['keydata']['qx'], public_key_array['keyset']['key']['keydata']['qy'])

    sign_data = message_array['data']
    verified = AuthSign(challenge, sign_data,Q)
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
    dec = DecryptGostOpen(curve, P, c)
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
    # print(writer.transport.get_extra_info('sock'))
    # print(reader.transport.get_extra_info('sockname'))
    message_array = cmd_scheme.decode('CmdFile', message)
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

session_list=[]
challenge = RandomString(10)
loop = asyncio.get_event_loop()
port = 22222
loop.create_task(asyncio.start_server(listener, 'localhost', port))
# loop.create_task(connect(22222, loop))
# loop.create_task(connect(33333, loop))
loop.run_forever()

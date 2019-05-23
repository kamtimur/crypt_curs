import asyncio
import asn1tools
import random
import string
from eleptic import *
from pygost.gost3410 import CURVE_PARAMS #p, q, a, b, x, y
from random import randrange
from pygost.utils import *
import random
from pygost.gost34112012 import GOST34112012 as GostHash

message = 'Hello World!'
cmd_scheme = asn1tools.compile_files('schemes/cmd_scheme.asn')
challenge_scheme = asn1tools.compile_files('schemes/challenge_scheme.asn')
gost_sign_file = asn1tools.compile_files('schemes/gost_sign.asn')


#gen keys
enhex = lambda x: ''.join(hex(ord(i))[2:] for i in x)  # записываем шестнадцатиричное представление ключа

abc = 'abcdefghijklmnopqrstuvwxyz'
randomKey = lambda: enhex(
    ''.join(random.choice(abc) for i in range(32)))  # генерируем случайную последвательность символов

key = hexdec(randomKey())
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
keystr = key.decode("utf-8")
print(keystr)


def RandomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))



def GenSign(message):
    hash_message = GostHash(message).digest()
    print(hash_message.hex())
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

def AuthSign(file, sign):
    sign_file = open(sign, 'rb')
    sign_data = sign_file.read()
    sign_str = gost_sign_file.decode('GostSignFile', sign_data)
    r = sign_str['keyset']['key']['ciphertext']['r']
    s = sign_str['keyset']['key']['ciphertext']['s']

    if r > curve.q or s > curve.q:
        return False

    source_file = open(file, "rb")
    readFile = source_file.read()
    hash = GostHash(readFile).digest()
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



def HelloResponse(reader, writer):
    #валидировать открытый ключ
    ChallengeRequest(reader, writer)


def ChallengeResponse(message_array, reader, writer):
    challenge = message_array['data']
    print('challenge arrived',challenge)
    # подписать challenge и отправить его
    sign = GenSign(challenge)

    message = GenerateCmd('challenge_response',sign)
    writer.write(message)


def ChallengeRequest(reader, writer):
    challenge = RandomString(10)
    challenge_data = challenge_scheme.encode('Challenge',
                                {
                                    'challenge': challenge
                                })
    message = GenerateCmd('challenge',challenge_data)

    message = writer.write(message)
    print('massage sent', message)

def HelloRequest(reader, writer):
    pass
    #отправить открытый ключ
    #послать свое hello


def VerifyChallenge(message_array, reader, writer):
    #проверить challenge и отправить разрешение и свой открытый ключ
    message = GenerateCmd('allow_con',bytearray(''.encode()))
    writer.write(message)

def EstablishSessionKey(message_array, reader, writer):
    #сгенерировать сессионный ключ зашифровать его открытым ключом, взять хэш подписать и отправить
    message = GenerateCmd('est_ses_key',bytearray(''.encode()))
    writer.write(message)

def SetSessionKey(message_array, reader, writer):
    #получить сессионный ключ, расшифровать его, проверить подпись, установить его
    message = GenerateCmd('enc_success',bytearray(''.encode()))
    writer.write(message)

def StartSession(message_array, reader, writer):
    print('session established')


def ProcessInMes(message,reader, writer):
    message_array = cmd_scheme.decode('CmdFile', message)
    cmd = message_array['command']
    print('cmd rec ', cmd)
    if cmd == 'hello':
        HelloResponse(reader, writer)
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
    if cmd == 'est_ses_key':
        SetSessionKey(message_array, reader, writer)
        return True
    if cmd == 'enc_success':
        StartSession(message_array, reader, writer)
        return True
    print('command invalid', cmd)
    return False


async def listener(reader, writer):
    while True:
        response = (await reader.read(8192))
        print('message rec', response)
        ProcessInMes(response,reader, writer)


async def client(port, loop):
    reader, writer = await asyncio.open_connection('localhost', port, loop=loop)

    cmd_message = GenerateCmd('hello',bytearray(''.encode()))
    print('Send: %r' % cmd_message)
    writer.write(cmd_message)
    while True:
        response = (await reader.read(8192))
        print('message rec', response)
        ProcessInMes(response,reader, writer)


loop = asyncio.get_event_loop()
# port = input("input port to listen\n")
port = 11111;
loop.create_task(asyncio.start_server(listener, 'localhost', port))
# port = input("input port to connect\n")
loop.run_until_complete(client(port, loop))
loop.run_forever()

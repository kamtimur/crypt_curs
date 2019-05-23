import asyncio
import asn1tools
import random
import string

message = 'Hello World!'
cmd_scheme = asn1tools.compile_files('schemes/cmd_scheme.asn')
challenge_scheme = asn1tools.compile_files('schemes/challenge_scheme.asn')

def RandomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

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
    message = GenerateCmd('challenge_response',bytearray(''.encode()))
    writer.write(message)
    #подписать challenge и отправить его


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
loop.create_task(asyncio.start_server(listener, 'localhost', 15555))
loop.run_until_complete(client(15555, loop))
loop.run_forever()

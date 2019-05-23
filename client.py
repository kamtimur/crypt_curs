import asyncio

message = 'Hello World!'

async def handle_client(reader, writer):
    while True:
        request = (await reader.read(255)).decode()
        writer.write(request.encode())

async def tcp_echo_client(port, loop):
    try:
        reader, writer = await asyncio.open_connection('localhost', port,loop=loop)
    except 
    print('Send: %r' % message)
    writer.write(message.encode())

    while True:

        data = await reader.read(100)
        print('Received: %r' % data.decode())
        writer.write(data)



loop = asyncio.get_event_loop()
loop.create_task(asyncio.start_server(handle_client, 'localhost', 15555))
loop.run_until_complete(tcp_echo_client(15556, loop))

loop.run_forever()

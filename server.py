import asyncio
async def handle_client(reader, writer):
    while True:
        request = (await reader.read(255)).decode()
        writer.write(request.encode())

loop = asyncio.get_event_loop()
loop.create_task(asyncio.start_server(handle_client, 'localhost', 15555))
loop.run_forever()
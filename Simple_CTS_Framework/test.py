import asyncio, telnetlib3


async def shell(reader, writer):
    """
    while True:
        # read stream until '?' mark is found
        outp = yield from reader.read(1024)
        if not outp:
            # End of File
            break
        elif '?' in outp:
            # reply all questions with 'y'.
            writer.write('y')

        # display all server output
        print(outp, flush=True)
    """
    outp = await reader.read(1024)
    print(outp, flush=False)

    writer.write('testuser\n')
    outp = await reader.read(1024)
    print(outp, flush=False)

    await asyncio.sleep(3)
    writer.write('test1234\n')
    #outp = await reader.read(1024)
    #print(outp, flush=False)

    await asyncio.sleep(3)
    writer.write('ls -al\n')
    await asyncio.sleep(3)
    outp = await reader.read(4096)
    # print(len(outp))
    print(outp, flush=False)

    # EOF
    print()


loop = asyncio.get_event_loop()
coro = telnetlib3.open_connection('192.168.61.129', 23, shell=shell)
reader, writer = loop.run_until_complete(coro)
loop.run_until_complete(writer.protocol.waiter_closed)

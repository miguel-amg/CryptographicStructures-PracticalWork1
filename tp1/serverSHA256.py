import asyncio
from spongeSHAKE256 import aead_shake_encrypt, aead_shake_decrypt

server_ip = 'localhost'
server_port = 2003

async def recMsg(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"Conexão estabelecida com {addr!r}")

    ad = "Dados associados"
    key = "chave_secreta"

    while True:
        data = await reader.read(1024)
        if not data:
            break
        
        print(f"Mensagem recebida: {data!r}")
        decrypted = aead_shake_decrypt(data[:-16], ad, key, data[-16:])
        print(f"Mensagem recebida {decrypted!r} de {addr!r}.")

        response = f"Echo: {decrypted}"
        encrypted_response = aead_shake_encrypt(response, ad, key)
        writer.write(encrypted_response["ciphertext"] + encrypted_response["tag"])
        await writer.drain()

    writer.close()
    await writer.wait_closed()

async def main():
    server = await asyncio.start_server(recMsg, server_ip, server_port)
    async with server:
        await server.serve_forever()

asyncio.run(main())
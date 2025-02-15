import asyncio
from tp1.experimental.spongeSHAKE256 import aead_shake_encrypt, aead_shake_decrypt

server_ip = 'localhost'
server_port = 2003

async def sendMsg(writer, reader, message, ad, key):
    encrypted = aead_shake_encrypt(message, ad, key)
    print("Encriptado:", encrypted["ciphertext"])
    writer.write(encrypted["ciphertext"] + encrypted["tag"])
    await writer.drain()
    print('Mensagem enviada com sucesso.')

    data = await reader.read(1024)
    decrypted = aead_shake_decrypt(data[:-16], ad, key, data[-16:])
    print(f'Recebido: {decrypted!r}')

async def main():
    reader, writer = await asyncio.open_connection(server_ip, server_port)
    print(f"Conexão ao servidor (ip:{server_ip}, porta:{server_port}) estabelecida.")
    
    ad = "Dados associados"
    key = "chave_secreta"
    
    while True:
        msg_data = input("Enviar mensagem para o servidor: ")
        await sendMsg(writer, reader, msg_data, ad, key)

asyncio.run(main())
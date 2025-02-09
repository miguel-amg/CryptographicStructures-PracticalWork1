# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Bibliotecas
import asyncio, cryptography 

# Valores hardcoded alteráveis
server_ip = 'localhost'
server_port = 2003

# Lidar com uma mensagen recebida
async def recMsg(reader, writer):
    # Ler a mensagem
    data = await reader.read(100)
    message = data.decode()
    addr = writer.get_extra_info('peername')
    print(f"Mensagem recebida {message!r}. De: {addr!r}.")

    # Enviar mensagem igual de volta
    print(f"Mensagem enviada (automatico): {message!r}")
    writer.write(data)
    await writer.drain()

async def main():
    # Iniciar o servidor
    print("Aplicacao servidor iniciada")
    server = await asyncio.start_server(recMsg, server_ip, server_port)

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f'Serving on {addrs}')

    async with server:
        await server.serve_forever()

asyncio.run(main())
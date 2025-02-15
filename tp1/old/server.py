# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Este ficheiro contem o codigo da aplicação servidor

# Bibliotecas
import asyncio

# Valores hardcoded alteráveis
server_ip = 'localhost'
server_port = 2003

# Lidar com uma mensagen recebida
async def recMsg(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"Conexão estabelecida com {addr!r}")

    while True:
        data = await reader.read(100) # Esperar por mensagem
        
        if not data:
            break  # Coneccao do cliente desligada

        message = data.decode()
        print(f"Mensagem recebida {message!r} de {addr!r}.")

        # Enviar a mesma mensagem de volta
        print(f"Mensagem enviada (automático): {message!r}")
        writer.write(data)
        await writer.drain()

    print(f"Conexão fechada com {addr!r}")
    writer.close()
    await writer.wait_closed()

async def main():
    # Iniciar o servidor
    print("Aplicacao servidor iniciada")
    server = await asyncio.start_server(recMsg, server_ip, server_port)

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f'Serving on {addrs}')

    async with server:
        await server.serve_forever()

asyncio.run(main())
# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Este ficheiro contem o codigo da aplicação cliente

# Bibliotecas
import asyncio

# Valores hardcoded alteráveis
server_ip = 'localhost'
server_port = 2003

# Enviar mensagem para o servidor
async def sendMsg(writer, reader, message):
    try:
        print(f'A enviar: {message!r}')
        writer.write(message.encode())
        await writer.drain()
        print('Mensagem enviada com sucesso.')

        data = await reader.read(100)
        print(f'Recebido: {data.decode()!r}')

    except Exception as e:
        print(f"Erro ao enviar ou receber mensagem: {e}")

# Função principal
async def main():
    try:
        # Iniciar o cliente
        print("Aplicacao cliente iniciada.")
        reader, writer = await asyncio.open_connection(server_ip, server_port)
        print(f"Conexão ao servidor (ip:{server_ip}, porta:{server_port}) estabelecida.")
        print("Escrever 'exit' para sair.")
        print()

        # Cliente a correr
        while True:
            msg_data = input("Enviar mensagem para o servidor: ")
            await sendMsg(writer, reader, msg_data)
            
    except ConnectionRefusedError:
        print("Erro: Nao foi possivel conectar ao servidor.")
    except Exception as e:
        print(f"Erro inesperado: {e}")
    finally:
        if 'writer' in locals():
            writer.close()
            await writer.wait_closed()

# Iniciar a aplicação
asyncio.run(main())

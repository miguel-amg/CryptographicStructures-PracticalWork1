# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Este ficheiro contem o codigo da aplicação servidor

# Bibliotecas
import asyncio
import sys
import kdf
import AEAD

#########################################################################################
# Valores hardcoded alteráveis
server_ip = 'localhost'
server_port = 2003

# Modo debug
view_tags = False # Permite visualizar o valor das tags
view_cyphertexts = False # Permite visualizar o valor dos ciphertexts
view_details = True # Informacoes extra sobre o funcionamento 

# Informações para derivação de chaves (Segredos partilhados entre o emmiter e receiver)
SALT = b"salt-fixo-para-utilizar"
INFO_KEY = b"info-chave"
GEN_KEY_SIZE = 30
ASSOCIATED_DATA = "associated-data"

# Pode ser modificado
INFO_NONCE = b"info-nonce"
padding_mode = "pkcs" # Modos explicados abaixo (Tem de ser equivalente de ambos os lados)

# Valores possiveis para o padding_mode:
#  pkcs - Permite deteção de modificação da mensagem no recetor da mensagem) 
#  zero - Utiliza zero-padding em que apenas se consegue verificar a tag comparando as tags de cifragem e decifragem    
#########################################################################################

# Lidar com uma mensagen recebida
async def recMsg(reader, writer):
    # Instanciar AEAD
    aead_cipher = AEAD.aead()

    # Obter a chave
    shared_key = sys.argv[1]
    shared_key_bytes = shared_key.encode()

    # Gerar a key
    aead_key = kdf.derive_key(shared_key_bytes, GEN_KEY_SIZE, SALT, INFO_KEY)
    print("[RECEIVER] Chave gerada.")
    aead_nounce = kdf.derive_key(shared_key_bytes, GEN_KEY_SIZE, SALT, INFO_NONCE)
    print("[RECEIVER] Nounce gerado.")

    # Receber comunicação do cliente
    addr = writer.get_extra_info('peername')
    print(f"[RECEIVER] Conexão estabelecida com {addr!r}")

    # Receber mensagens
    while True:
        data = await reader.read(100) # Esperar por mensagem
    
        if not data:
            break  # Coneccao do cliente desligada

        # Modo debug
        if(view_cyphertexts):
            print(f"[RECEIVER-DEBUG] Ciphertext recebido: {data}")

        originaltext_bytes, decrypt_tag = aead_cipher.decrypt(data, ASSOCIATED_DATA, aead_key, padding_mode)
        originaltext = originaltext_bytes.decode() # Passar o plaintext para texto
        print(f"[RECEIVER] Mensagem decifrada: {originaltext!r} enviada por {addr!r}.")

        # Visualizar a tag caso necessário
        if(view_tags):
            print(f"[RECEIVER-DEBUG] Tag da mensagem decifrada: {decrypt_tag!r} enviada por {addr!r}.")

        # Enviar a mesma mensagem de volta
        ciphertext_send, encrypt_tag = aead_cipher.encrypt(originaltext, ASSOCIATED_DATA, aead_key, aead_nounce, padding_mode)
        print(f"[RECEIVER] Mensagem espelhada enviada (automático): {originaltext!r}")
        writer.write(data)
        await writer.drain()

        # Modo debug
        if(view_cyphertexts):
            print(f"[RECEIVER-DEBUG] Ciphertext enviado: {ciphertext_send}")
        if(view_tags):
            print(f"[RECEIVER-DEBUG] Tag da mensagem enviada: {encrypt_tag}")

    print(f"[RECEIVER] Conexão fechada com {addr!r}")
    writer.close()
    await writer.wait_closed()

async def main():
    # Verificar se a chave foi recebida como argumento
    if len(sys.argv) < 2:
        print("[RECEIVER] Erro: Chave em falta!")
        print("[RECEIVER] Uso: python receiver.py <chave>")
        print("[RECEIVER] Nota: Recomenda-se utilizar a mesma chave para o servidor e o cliente.")
        sys.exit(1)

    # Iniciar o servidor
    print("[RECEIVER] Aplicacao servidor iniciada.")
    
    # Modo debug
    if(view_details):
        print("[RECEIVER-DEBUG] Modo de padding: " + str(padding_mode) + ", tamanho da chave gerada: " + str(GEN_KEY_SIZE) + '.')

    # Iniciar o servidor
    server = await asyncio.start_server(recMsg, server_ip, server_port)

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f'[RECEIVER] A servir em {addrs}')

    async with server:
        await server.serve_forever()

asyncio.run(main())

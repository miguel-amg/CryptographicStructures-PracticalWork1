# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Este ficheiro contem o codigo da aplicação cliente

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
# (Tem de ser equivalente de ambos os lados)
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


# Enviar mensagem para o servidor
async def sendMsg(aead_cipher, writer, reader, message, aead_key, aead_nounce):
    try:
        print(f'[CLIENT] A enviar: {message!r}')
        
        # Realizar encrypt da mensagem
        ciphertext_send, encrypt_tag = aead_cipher.encrypt(message, ASSOCIATED_DATA, aead_key, aead_nounce, padding_mode)
        
        # Modo debug
        if(view_cyphertexts):
            print(f"[RECEIVER-DEBUG] Ciphertext enviado: {ciphertext_send}")
        if(view_tags):
            print(f"[RECEIVER-DEBUG] Tag da mensagem enviada: {encrypt_tag}")

        # Enviar a mensagem cifrada para o servidor
        writer.write(ciphertext_send)

        await writer.drain()
        print('[CLIENT] Mensagem cifrada enviada com sucesso.')

        data = await reader.read(100)
        originaltext, decrypt_tag = aead_cipher.decrypt(data, ASSOCIATED_DATA, aead_key, padding_mode)
        print(f'[CLIENT] Recebido: {originaltext.decode()}')

        # Modo debug
        if(view_cyphertexts):
            print(f"[RECEIVER-DEBUG] Ciphertext recebido: {data}")
        if(view_tags):
            print(f"[RECEIVER-DEBUG] Tag da mensagem enviada: {decrypt_tag}")

    except Exception as e:
        print(f"[CLIENT] Erro ao enviar ou receber mensagem: {e}")

# Função principal
async def main():
    print("[CLIENT] Aplicacao cliente iniciada.")
    
    # Modo debug
    if(view_details):
        print("[RECEIVER-DEBUG] Modo de padding: " + str(padding_mode) + ", tamanho da chave gerada: " + str(GEN_KEY_SIZE) + '.')

    # Instanciar AEAD
    aead_cipher = AEAD.aead()

    # Verificar se a chave foi recebida como argumento
    if len(sys.argv) < 2:
        print("[CLIENT] Erro: Chave em falta!")
        print("[CLIENT] Uso: python emmiter.py <chave>")
        print("[CLIENT] Nota: Recomenda-se utilizar a mesma chave para o servidor e o cliente.")
        sys.exit(1)

    # Chave recebida como argumento
    shared_key = sys.argv[1]
    shared_key_bytes = shared_key.encode()

    # Gerar a key
    aead_key = kdf.derive_key(shared_key_bytes, GEN_KEY_SIZE, SALT, INFO_KEY); print("[CLIENT] Chave gerada.")
    aead_nounce = kdf.derive_key(shared_key_bytes, GEN_KEY_SIZE, SALT, INFO_NONCE); print("[CLIENT] Nounce gerado.")

    try:
        # Iniciar o cliente
        print("[CLIENT] A conectar ao servidor.")
        reader, writer = await asyncio.open_connection(server_ip, server_port)
        print(f"[CLIENT] Conexão ao servidor (ip:{server_ip}, porta:{server_port}) estabelecida.")
        print("[CLIENT] Escrever 'exit' para sair.")
        print()

        # Cliente a correr
        while True:
            msg_data = input("[CLIENT] Enviar mensagem para o servidor: ")
            await sendMsg(aead_cipher, writer, reader, msg_data, aead_key, aead_nounce)
            
    except ConnectionRefusedError:
        print("[CLIENT] Erro: Nao foi possivel conectar ao servidor.")
        print("[CLIENT] Causas possiveis: Servidor desligado ou porta incorreta.")
    except Exception as e:
        print(f"[CLIENT] Erro inesperado: {e}")
    finally:
        if 'writer' in locals():
            writer.close()
            await writer.wait_closed()

# Iniciar a aplicação
asyncio.run(main())

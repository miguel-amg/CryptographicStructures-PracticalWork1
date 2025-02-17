# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Imports
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding

#############################################
# Valores alteraveis (hardcoded)
NOUNCESIZE = 16 # Tamanho do nounce em bytes
#############################################

# Classe que contém o codigo da cifra aead
class aead:
    # A cifra vai receber a mensagem (plaintext), dados associados (ad), uma chave (key)
    def encrypt(self, plaintext="", ad="", key_bytes=b''):
        # Verificação do input
        self._checkdata(plaintext, ad, key_bytes)

        # Preparação das variaveis
        plaintext_bytes = plaintext.encode() 
        ad_bytes = ad.encode() 
        iv = secrets.token_bytes(NOUNCESIZE) # O iv é o rate deste sponge (Gerar um nonce)
        blockSize = len(iv) # Tamanho do bloco

        # Preparação
        ad_padded = self.__AddPadding(ad_bytes, blockSize) 
        plaintext_padded = self.__AddPadding(plaintext_bytes, blockSize)

        # Execução do algoritmo de cifragem
        absorve_state = self.__absorve(iv, key_bytes, ad_padded) # Realizar o absorve
        result = self.__squeeze(plaintext_padded, absorve_state, blockSize, key_bytes, mode="encrypt")

        return iv + result[0], result[1]  # Inserir o nounce para depois ser utilizado na decifragem. Devolve (iv+ciphertext, tag)

    # A cifra vai receber a mensagem (ciphertext), dados associados (ad), uma chave (key)
    def decrypt(self, ciphertext_bytes=b'', ad="", key_bytes=b''):
        # Extrair o IV utilizado na cifragem apartir do ciphertext
        iv, ciphertext_bytes = ciphertext_bytes[:NOUNCESIZE], ciphertext_bytes[NOUNCESIZE:]

        # Verificação do input
        self._checkdata(ciphertext_bytes, ad, key_bytes)

        # Preparação das variaveis
        ad_bytes = ad.encode() 
        blockSize = len(iv) # Tamanho do bloco

        # Preparação
        ad_padded = self.__AddPadding(ad_bytes, blockSize) 

        # Execução do algoritmo de cifragem
        absorve_state = self.__absorve(iv, key_bytes, ad_padded) # Realizar o absorve
        plaintext_padded, tag = self.__squeeze(ciphertext_bytes, absorve_state, blockSize, key_bytes, mode="decrypt")

        # Remover o padding da cifragem
        unpadded_plaintext = self.__RemovePadding(plaintext_padded, blockSize)
        return unpadded_plaintext, tag

    # Método privado que adiciona padding a uma sequência de bytes (usando pkcs7) 
    # - Faz com que o tamanho do input seja multiplo do tamanho do bloco
    # - Permite detetar ataques de comprimento 
    # - Permite remoção fácil do padding. 
    def __AddPadding(self, input: bytes, blockSize: int) -> bytes:
        padder = padding.PKCS7(blockSize * 8).padder() # So trabalha com bits o pkcs7
        padded = padder.update(input) + padder.finalize()
        return padded

    # Método privado que remove padding
    def __RemovePadding(self, input_data: bytes, blockSize: int) -> bytes:
        unpadder = padding.PKCS7(blockSize * 8).unpadder()
        unpadded = unpadder.update(input_data) + unpadder.finalize()
        return unpadded

    # Metodo privado que realiza o absorve do sponge (Devolve o ultimo estado)
    def __absorve(self, starting_rate, key_bytes, padded_data):
        # Preparação para o absorve
        ad = padded_data
        blockSize = len(starting_rate)
        cycles = int(len(padded_data) / blockSize) 
        state = starting_rate + key_bytes
        state_size = len(state)

        # Iterações do absorve
        for n in range(cycles):
            # Aplicar a função F (shake-256)
            digest = hashes.Hash(hashes.SHAKE256(digest_size=state_size))
            digest.update(state) # Dar como input o estado atual
            state = digest.finalize() # Receber o output que passa a ser o proximo estado

            # Preparação para o OTP
            new_rate = state[:blockSize] # Extrair os primeiros rate bits do estado (rate do estado atual)
            state    = state[blockSize:] # Remover os primeiros rate bits do estado (criar espaço para o resultado)
            block    = ad[:blockSize]    # Extrair os primeiros rate bits dos metadados (bloco de dados do ad)
            ad       = ad[blockSize:]    # Remover os primeiros rate bits dos metadados (para iterar o ad)

            # Aplicar OTP
            xor_result = bytes(x ^ y for x, y in zip(new_rate, block)) # Realizar 'rate XOR metadados'
            state = xor_result + state
        
        return state

    # Metodo privado que realiza o squeeze do sponge
    # input_data: O que vai sendo inserido ao longo do squeeze
    def __squeeze(self, input_data, state, blockSize, key_bytes, mode="encrypt"):
        extracted_data = b''  # Resultado do squeeze
        cycles = int(len(input_data) / blockSize)  # Número de iterações
        state_size = len(state)  # Tamanho do state

        for n in range(cycles):
            # Extração do rate (keystream)
            rate = state[:blockSize]
            state = state[blockSize:]
            # Extração do próximo bloco de input_data
            input_block = input_data[:blockSize]
            input_data = input_data[blockSize:]
            # Calcular a saída (XOR entre rate e input_block)
            xor_result = bytes(x ^ y for x, y in zip(rate, input_block))
            extracted_data += xor_result

            # Atualização do state: 
            # Se estamos encriptando, o bloco usado é o xor_result (que é o ciphertext)
            # Se estamos decifrando, o bloco usado deve ser o input_block (o ciphertext recebido)
            if mode == "encrypt":
                state = xor_result + state
            else:
                state = input_block + state

            # Atualizar o state aplicando a função F (SHAKE256)
            digest = hashes.Hash(hashes.SHAKE256(digest_size=state_size))
            digest.update(state)
            state = digest.finalize()

        # Processar a última iteração separadamente (para key-mixing e tag)
        # Aqui, o mesmo procedimento se aplica: usamos o mesmo update conforme o modo
        if cycles > 0:
            rate = state[:blockSize]
            state = state[blockSize:]
            input_block = input_data[:blockSize]
            input_data = input_data[blockSize:]
            xor_result = bytes(x ^ y for x, y in zip(rate, input_block))
            extracted_data += xor_result
            if mode == "encrypt":
                state = xor_result + state
            else:
                state = input_block + state
            digest = hashes.Hash(hashes.SHAKE256(digest_size=state_size))
            digest.update(state)
            state = digest.finalize()
        # A tag é gerada fazendo XOR final do state com a chave
        key_for_tag = (key_bytes * ((state_size // len(key_bytes)) + 1))[:state_size]
        tag = bytes(x ^ y for x, y in zip(state, key_for_tag))
        return extracted_data, tag


    # Metodo privado que verifica os dados recebidos
    def _checkdata(self, plaintext, ad, key_bytes):
        if not plaintext:
            raise ValueError("Erro: O `plaintext` não pode estar vazio.")
        if not ad:
            raise ValueError("Erro: O `ad` (Associated Data) não pode estar vazio.")
        if not key_bytes:
            raise ValueError("Erro: A `key` (chave) não pode estar vazia.")

# Fazer testes
plaintext = "plaintextplaintextplaintextplaintext"
ad = "adadadadaadadadadaadadadadaadadadada"
chave = "chavechavechavechavechavechave"
chave_bytes = chave.encode() 

cifra = aead()
ciphertext, encrypt_tag = cifra.encrypt(plaintext, ad, chave_bytes)
originaltext, decrypt_tag = cifra.decrypt(ciphertext, ad, chave_bytes)

print(originaltext)

# print("Tamanho da key:" + str(len(chave)))
# print("Ciphertext:" + str(ciphertext))
# print("Tag:" + str(tag))
# print("Tamanho do ciphertext:" + str(len(ciphertext)))
# print("Tamanho da tag:" + str(len(tag)))
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
    def encrypt(self, plaintext="", ad="", key=""):
        # Verificação do input
        self._checkdata(plaintext, ad, key)

        # Preparação das variaveis
        plaintext_bytes = plaintext.encode() 
        ad_bytes = ad.encode() 
        key_bytes = key.encode() # A key é a capacidade do sponge
        iv = secrets.token_bytes(NOUNCESIZE) # O iv é o rate deste sponge (Gerar um nonce)
        blockSize = len(iv) # Tamanho do bloco

        # Preparação
        ad_padded = self.__AddPadding(ad_bytes, blockSize) 
        plaintext_padded = self.__AddPadding(plaintext_bytes, blockSize)

        # Execução do algoritmo de cifragem
        absorve_state = self.__absorve(iv, key_bytes, ad_padded) # Realizar o absorve
        result = self.__squeeze(plaintext_padded, absorve_state, blockSize, key_bytes) # Realizar o squeeze

        return result

    # Método privado que adiciona padding a uma sequência de bytes (usando pkcs7) 
    # - Faz com que o tamanho do input seja multiplo do tamanho do bloco
    # - Permite detetar ataques de comprimento 
    # - Permite remoção fácil do padding. 
    def __AddPadding(self, input: bytes, blockSize: int) -> bytes:
        padder = padding.PKCS7(blockSize * 8).padder() # So trabalha com bits o pkcs7
        padded = padder.update(input) + padder.finalize()
        return padded

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
    def __squeeze(self, input_data, state, blockSize, key_bytes):  
        # Variaveis
        extracted_data = b'' # Resultado do squeeze
        cycles = int(len(input_data) / blockSize) # Numero de iterações a ser realizado
        state_size = len(state) # Tamanho do state

        # Realizar o squeeze
        for n in range(cycles):
            if(n<cycles):
                rate = state[:blockSize]  # Extrair os primeiros rate bits do estado
                state = state[blockSize:] # Remover os primeiros rate bits do estado
                input_block = state[:blockSize] # Extrair os primeiros rate bits dos dados a ser inseridos
                input_data = state[blockSize:]  # Remover os primeiros rate bits dos dados a ser inseridos

                # OTP/XOR
                xor_result = bytes(x ^ y for x, y in zip(rate, input_block)) # Realizar 'rate XOR input_block'
                extracted_data = extracted_data +  xor_result # Armazenar o resultado do xor (ciphertext em modo cifragem ou plaintext em modo decifragem) 
                state = xor_result + state # O state passa a encorporar o resultado do xor

                # Aplicar a função F (shake-256)
                digest = hashes.Hash(hashes.SHAKE256(digest_size=state_size)) 
                digest.update(state) # Dar como input o estado atual
                state = digest.finalize() # Receber o output que passa a ser o proximo estado
            
            # Na ultima iteração a capacidade leva xor com a chave
            if(n == cycles - 1):
                rate = state[:blockSize]  # Extrair os primeiros rate bits do estado
                state = state[blockSize:] # Remover os primeiros rate bits do estado
                input_block = state[:blockSize] # Extrair os primeiros rate bits dos dados a ser inseridos
                input_data = state[blockSize:]  # Remover os primeiros rate bits dos dados a ser inseridos

                # Aplicar XOR entre `capacity` e `key`
                rate_xor = bytes(x ^ y for x, y in zip(rate, input_block))  
                state = bytes(x ^ y for x, y in zip(state, key_bytes)) 
                state = rate_xor + state # Adicionar o resultado do xor ao state

            # Obter a tag fazendo xor do resultado final com a chave
            tag = bytes(x ^ y for x, y in zip(state, key_bytes))

        # Devolver um tuplo com o resultado e a tag
        return extracted_data, tag

    # Metodo privado que verifica os dados recebidos
    def _checkdata(self, plaintext, ad, key):
        if not plaintext:
            raise ValueError("Erro: O `plaintext` não pode estar vazio.")
        if not ad:
            raise ValueError("Erro: O `ad` (Associated Data) não pode estar vazio.")
        if not key:
            raise ValueError("Erro: A `key` (chave) não pode estar vazia.")

# Fazer testes
plaintext = "plaintextplaintextplaintextplaintext"
ad = "adadadadaadadadadaadadadadaadadadada"
chave = "chavechavechavechavechavechave"

shake = aead()
ciphertext,tag = shake.encrypt(plaintext, ad, chave)

# print("Tamanho da key:" + str(len(chave)))
# print("Ciphertext:" + str(ciphertext))
# print("Tag:" + str(tag))
# print("Tamanho do ciphertext:" + str(len(ciphertext)))
# print("Tamanho da tag:" + str(len(tag)))
# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Imports
import sys
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding

#############################################
# Valores alteraveis (hardcoded)
NOUNCESIZE = 16 # Tamanho do nounce default
#############################################

# Classe que contém o codigo da cifra aead (Tipos de padding: zero ou pkcs) 
# Utiliza zero padding por default
class aead:
    # A cifra vai receber a mensagem (plaintext), dados associados (ad), uma chave (key)
    def encrypt(self, plaintext="", ad="", key_bytes=b'', iv=None, paddingType="zero"):
        # Se não for passado um IV, é gerado um nonce default
        if iv is None:
            iv = secrets.token_bytes(NOUNCESIZE)

        # Verificação do input
        self._checkdata(plaintext, ad, key_bytes)

        # Preparação das variaveis
        plaintext_bytes = plaintext.encode() 
        ad_bytes = ad.encode() 
        blockSize = len(iv) # Tamanho do bloco

        # Preparação (Adicionar padding)
        ad_padded = b''
        plaintext_padded = b''
        if (paddingType == "zero"):
            ad_padded = self.__AddPaddingZero(ad_bytes, blockSize) 
            plaintext_padded = self.__AddPaddingZero(plaintext_bytes, blockSize)
        elif (paddingType == "pkcs"):
            ad_padded = self.__AddPaddingPKCS(ad_bytes, blockSize) 
            plaintext_padded = self.__AddPaddingPKCS(plaintext_bytes, blockSize)
        else:
            raise ValueError("[AEAD] Tipo de padding desconhecido.")

        # Execução do algoritmo de cifragem
        absorve_state = self.__absorve(iv, key_bytes, ad_padded) # Realizar o absorve
        result = self.__squeeze(plaintext_padded, absorve_state, blockSize, key_bytes, mode="encrypt")

        # Cria um campo de 2 bytes com o tamanho do nonce
        nonce_length = len(iv).to_bytes(2, byteorder="big")

        # Resultado concatenado: [tamanho do nonce][nonce][ciphertext]
        return nonce_length + iv + result[0], result[1]

    # A cifra vai receber a mensagem (ciphertext), dados associados (ad), uma chave (key)
    def decrypt(self, ciphertext_bytes=b'', ad="", key_bytes=b'', paddingType="zero"):
        # Extrair os primeiros 2 bytes para obter o tamanho do nonce
        nonce_length = int.from_bytes(ciphertext_bytes[:2], byteorder="big")

        # Extrair o nonce
        iv = ciphertext_bytes[2:2+nonce_length]
        
        # Extrair o ciphertext
        ciphertext_bytes = ciphertext_bytes[2+nonce_length:]

        # Verificação do input
        self._checkdata(ciphertext_bytes, ad, key_bytes)

        # Preparação das variaveis
        ad_bytes = ad.encode() 
        blockSize = len(iv)

        # Preparação (Adicionar padding)
        ad_padded = b''
        if (paddingType == "zero"):
            ad_padded = self.__AddPaddingZero(ad_bytes, blockSize)
        elif (paddingType == "pkcs"):
            ad_padded = self.__AddPaddingPKCS(ad_bytes, blockSize)
        else:
            raise ValueError("Tipo de padding desconhecido.")

        # Execução do algoritmo de cifragem
        absorve_state = self.__absorve(iv, key_bytes, ad_padded) # Realizar o absorve
        plaintext_padded, tag = self.__squeeze(ciphertext_bytes, absorve_state, blockSize, key_bytes, mode="decrypt")

        # Remover o padding da cifragem
        unpadded_plaintext= b''
        if (paddingType == "zero"):
            unpadded_plaintext = self.__RemovePaddingZero(plaintext_padded, blockSize)
        elif (paddingType == "pkcs"):
            unpadded_plaintext = self.__RemovePaddingPKCS(plaintext_padded, blockSize)
        
        return unpadded_plaintext, tag

    # Método privado que adiciona padding a uma sequência de bytes (usando pkcs7) 
    # - Faz com que o tamanho do input seja multiplo do tamanho do bloco
    # - Permite detetar ataques de comprimento 
    # - Permite remoção fácil do padding. 
    def __AddPaddingPKCS(self, input: bytes, blockSize: int) -> bytes:
        padder = padding.PKCS7(blockSize * 8).padder() # So trabalha com bits o pkcs7
        padded = padder.update(input) + padder.finalize()
        return padded

    # Método privado que remove padding
    def __RemovePaddingPKCS(self, input_data: bytes, blockSize: int) -> bytes:
        unpadder = padding.PKCS7(blockSize * 8).unpadder()
        try:
            unpadded = unpadder.update(input_data) + unpadder.finalize()
        except ValueError as e:
            print("[AEAD] O algoritmo de padding PKCS7 detetou corrupção de dados.")
            sys.exit(1)  # Parar o algoritmo
        return unpadded

    # Metodo privado de zero padding
    def __AddPaddingZero(self, input_data: bytes, blockSize: int) -> bytes:
        remainder = len(input_data) % blockSize
        if remainder == 0:
            return input_data
        needed = blockSize - remainder
        return input_data + (b'\x00' * needed)

    # Metodo privado de remoção de zero padding
    def __RemovePaddingZero(self, input_data: bytes, blockSize: int) -> bytes:
        return input_data.rstrip(b'\x00')

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

        # Iterações normais do squeeze
        for n in range(cycles):
            rate        = state[:blockSize]      # Extrair os primeiros rate bits do estado (rate do estado atual)
            state       = state[blockSize:]      # Remover os primeiros rate bits do estado (rate do estado atual)
            input_block = input_data[:blockSize] # Extrair um bloco do input_data (ciphertext ou plaintext)
            input_data  = input_data[blockSize:] # Remover um bloco do input_data

            # Calcular a saída (XOR entre rate e input_block)
            xor_result = bytes(x ^ y for x, y in zip(rate, input_block))
            extracted_data += xor_result

            # Atualização do state: (Vamos utilizar o ciphertext em ambos para os estados estarem sincronizados)
            if mode == "encrypt":
                state = xor_result + state # Ao fazer cifragem, o bloco usado é o xor_result (que é o ciphertext)
            else:
                state = input_block + state # Ao fazer decifragem, o bloco usado é o input_block (o ciphertext recebido)

            # Atualizar o state (SHAKE256)
            digest = hashes.Hash(hashes.SHAKE256(digest_size=state_size))
            digest.update(state)
            state = digest.finalize()

        # Processar a última iteração (key-mixing e tag)
        if cycles > 0:
            rate = state[:blockSize]             # Extrair os primeiros rate bits do estado (rate do estado atual)
            state = state[blockSize:]            # Remover os primeiros rate bits do estado (rate do estado atual)
            input_block = input_data[:blockSize] # Extrair um bloco do input_data (ciphertext ou plaintext)
            input_data = input_data[blockSize:]  # Remover um bloco do input_data

            xor_result = bytes(x ^ y for x, y in zip(rate, input_block))
            extracted_data += xor_result

            # Atualização do state: (Vamos utilizar o ciphertext em ambos para os estados estarem sincronizados)
            if mode == "encrypt":
                state = xor_result + state # Ao fazer cifragem, o bloco usado é o xor_result (que é o ciphertext)
            else:
                state = input_block + state # Ao fazer decifragem, o bloco usado é o input_block (o ciphertext recebido)

            # Atualizar o state (SHAKE256)
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

# Função que permite testar o programa
def debugMode():
    plaintext = "PlaintextplaintextplaintextplaintexT"
    ad = "AdadadadaadadadadaadadadadaadadadadA"
    chave = "EhavechavechavechavechavechavE"
    chavefake = "FakefakefakefakefakefakefakefakefakE"
    chave_bytes = chave.encode() 
    chavefake_bytes = chavefake.encode() 
    nounce = b'teste'

    cifra = aead()
    ciphertext, encrypt_tag = cifra.encrypt(plaintext, ad, chave_bytes, nounce, "pkcs")
    originaltext, decrypt_tag = cifra.decrypt(ciphertext, ad, chave_bytes, "pkcs")

    print("Tag de cifragem: " + str(encrypt_tag))
    print("Tag de decifragem: " + str(decrypt_tag))
    print("Mensagem original: " + str(plaintext))
    print("Mensagem decifrada: " + str(originaltext))
    print("CipherText: " + str(ciphertext))

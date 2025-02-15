# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Imports
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding

#############################################
# Valores alteraveis (hardcoded)
NOUNCESIZE = 16 # Tamanho do nounce em bytes
#############################################

# Classe que contém o codigo da cifra aead
class aead:
    # Construtor parametrizado da classe (mengsagem, dados associados, chave, )
    def __init__(self, plaintext="", ad="", key=""):
        # Variaveis recebidas
        self.plaintext = plaintext  # Os dados do plaintext vão ser utilizados no squeeze
        self.ad = ad                # Os dados do AD vão ser alimentados no absorve
        self.key = key              # A chave é a capacidade

        # Variaveis em bytes
        self.ad_bytes = ad.encode() 
        self.plaintext_bytes = plaintext.encode() 
        self.key_bytes = key.encode()    # A chave é a Capacidade
        self.iv = os.urandom(NOUNCESIZE) # O iv é o rate deste sponge (Gerar um nonce)
        
        # Valores uteis
        self.blockSize = len(self.iv)   # O tamanho do bloco é o tamanho do rate
        self.sec_coef = len(self.iv)/2  # Coeficiente de segurança é metade dos bytes do rate 

    # A cifra vai receber a mensagem (plaintext), dados associados (ad), uma chave (key) e o nounce
    def cipher(self):
        # Execução do sponge
        ad_padded = self.__AddPadding(self.ad_bytes, self.blockSize) 
        absorve_state = self.__absorve(ad_padded) # Realizar o absorve
        self.__squeeze(absorve_state) # Realizar o squeeze

    # Método privado que adiciona padding a uma sequência de bytes (usando pkcs7) 
    # - Faz com que o tamanho do input seja multiplo do tamanho do bloco
    # - Permite detetar ataques de comprimento 
    # - Permite remoção fácil do padding. 
    def __AddPadding(self, input: bytes, blockSize: int) -> bytes:
        padder = padding.PKCS7(blockSize * 8).padder()
        padded = padder.update(input) + padder.finalize()
        return padded

    # Metodo privado que realiza o absorve do sponge (Devolve o ultimo estado)
    def __absorve(self, ad_padded: bytes):
        # Preparação para o absorve
        ad = ad_padded
        cycles = int(len(ad_padded) / self.blockSize) 
        state = self.iv + self.key_bytes
        state_size = len(state)
        rate_size = len(self.iv)

        # Iterações do absorve
        for n in range(cycles):
            # Aplicar a função F (shake-256)
            digest = hashes.Hash(hashes.SHAKE256(digest_size=state_size)) # O resultado do shake deve ser o tamanho do estado
            digest.update(state) # Dar como input o estado atual
            state = digest.finalize() # Receber o output que passa a ser o proximo estado

            # Preparação para o OTP
            rate = state[:rate_size]  # Extrair os primeiros rate bits do estado
            state = state[rate_size:] # Remover os primeiros rate bits do estado
            block = ad[:rate_size]    # Extrair os primeiros rate bits dos metadados
            ad = ad[rate_size:]       # Remover os primeiros rate bits dos metadados

            # Aplicar OTP
            xor_result = bytes(x ^ y for x, y in zip(rate, block)) # Realizar 'rate XOR metadados'
            state = xor_result + state
        
        return state

    # Metodo privado que realiza o squeeze do sponge
    # Parametros:
    # absorbed_data: O que vai sendo inserido ao longo do squeeze
    # extracted_data: O que vai sendo extraido ao longo do squeeze
    def __squeeze(self, absorbed_data, extracted_data):  
        # Plaintext a ser utilizado
        plaintext_copy = plaintext



    # Metodo privado que obtem a tag
    def __buildTag(self):  
        print()

# Fazer testes
plaintext = "plaintextplaintextplaintextplaintext"
ad = "adadadadaadadadadaadadadadaadadadada"
chave = "chavechavechavechavechavechave"

correr = aead(plaintext, ad, chave)
correr.cipher()
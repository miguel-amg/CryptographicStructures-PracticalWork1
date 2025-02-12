# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Imports
import sys
import os
from cryptography.hazmat.primitives import hashes

# Classe que contém o codigo da cifra aead
class aead_shake_cypher:
    # Construtor parametrizado da classe (mengsagem, dados associados, chave, )
    def __init__(self, plaintext="", ad="", key=""):
        self.plaintext = plaintext.encode() # Passar o plaintext para bytes
        self.ad = ad.encode # Passar a ad para bytes
        self.key = chave.encode # Passar a chave para bytes
        self.iv = os.urandom(16) # Gerar um nounce 

    # A cifra vai receber a mensagem (plaintext), dados associados (ad), uma chave (key) e o nounce
    def shake(plaintext, ad , key, nounce):
        block_size = len(iv) # Tamanho em bytes do bloco
        print("Tamanho do bloco:" + str(block_size))

        # ------------ Primeiro vamos obter o estado ------------  
        iv = nounce # O iv é o nounce nesta cifra
        key_bytes = str.encode(key)  # Converter a chave para bytes
        state = iv + key_bytes  # Concatenar IV (bytes) e key (bytes)

        print("iv:" + str(iv))
        print("key_bytes:" + str(key_bytes))
        print(state)

        # -------------------------------------------------------


        # Instancia do shake256 em modo XOFHash (que permite obter um output de tamanho variavel)
        # O tamamho maximo possivel do output foi definido para o maximo do sistema
        digest = hashes.Hash(hashes.SHAKE256(digest_size=block_size))
        digest.update(state) 
        result = digest.finalize() 

        print(result)
        print(len(result))

# FAZER PADING Á MENSAGEM

# Fazer testes
nounce = os.urandom(12) # Geramos um valor aleatorio de tamanho 12 bytes
plaintext = ""
ad = ""
chave = ""

aead_shake_cypher()
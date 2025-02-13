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
        self.plaintext = plaintext 
        self.ad = ad 
        self.key = key  
        self.plaintext_bytes = plaintext.encode() # Passar o plaintext para bytes
        self.ad_bytes = ad.encode() # Passar a ad para bytes
        self.key_bytes = key.encode() # Passar a chave para bytes
        self.iv = os.urandom(16) # Gerar um nonce 

    
    
    # A cifra vai receber a mensagem (plaintext), dados associados (ad), uma chave (key) e o nounce
    def shake(self):
        block_size = len(self.iv) # Tamanho em bytes do bloco
        print("Tamanho do bloco:" + str(block_size))

        # ------------ Primeiro vamos obter o estado ------------  
        state = self.iv + self.key_bytes  # Concatenar IV (bytes) e key (bytes)

        print("iv:" + str(self.iv))
        print("key_bytes:" + str(self.key_bytes))
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
plaintext = "asd"
ad = "ola"
chave = "chave"

correr = aead_shake_cypher(plaintext, ad, chave)
correr.shake()
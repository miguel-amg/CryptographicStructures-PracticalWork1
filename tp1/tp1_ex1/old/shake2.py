# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Imports
import sys
import os
from cryptography.hazmat.primitives import hashes

class SpongeSHAKE256:
    def __init__(self,rate = 136,capacity = 64):
        self.rate = rate #1088 bits
        self.capacity = capacity #512 bits -> metade destes bits sao o coeficiente de segurança
        self.state = bytearray(rate + capacity) #capacidade = b - r -> b = r + c 
        #b is called width of f
        self.vi = os.urandom(16) #inicialização do bloco de estados
        
         
    #The function f maps strings of a single, fixed length, denoted by b, to strings of the same length
    #function f is invertible, i.e., a permutation, although the sponge construction does not require f to be invertible.
        
    def permute(self):
        digest = hashes.Hash(hashes.SHAKE256(digest_size=len(self.state)))
        digest.update(self.state)
        self.state = bytearray(digest.finalize())
        
    #primeiro a mensagem é padded 
    #pad, is a function that produces padding, i.e., a string with an appropriate length to append to another string.
    # Within the sponge construction, padding is appended to the message to ensure that it can be partitioned into a sequence of r-bit strings.
    
    def _pad(self, data):
        """
        Aplica o padding pad10*1 à mensagem.
        """
        # Calcula o número de bytes necessários para o padding
        padding_length = self.rate - (len(data) % self.rate)
        
        # Se o padding_length for 0, adiciona um bloco completo de padding
        if padding_length == 0:
            padding_length = self.rate
        
        # Cria o padding: 0x80 (bit 1) + zeros + 0x01 (bit 1 no final)
        padding = bytearray([0x80] + [0x00] * (padding_length - 2) + [0x01])
        
        # Retorna a mensagem com o padding
        return data + padding
    
    
    #the SPONGE[f, pad, r] function is specified by Algorithm 8 on (M, d), where M is the input message to the sponge function, and d is the desired length of the output in bits. The width b is determined by the choice of f


    def absorb(self,data):
        
        padded_message = self._pad(data)
        
        # o plaintext é absorvid num bloco de estado com tamanho b
        
        for i in range(0, len(padded_message), self.rate):
            block = padded_message[i:i+self.rate]
            for j in range(len(block)):
                self.state[j] ^= block[j]
            self._permute()
            
    #...
    
    
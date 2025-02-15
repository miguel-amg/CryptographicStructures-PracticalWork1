import os
from cryptography.hazmat.primitives import hashes
from keccakHash import KeccakHash

class SpongeSHAKE256:
    def __init__(self, rate=136, capacity=64):
        self.rate = rate  # Tamanho do rate em bytes (SHAKE-256 usa 136 bytes)
        self.capacity = capacity  # Capacidade em bytes (64 bytes para SHAKE-256)
        self.state = bytearray(rate + capacity)  # Estado interno (rate + capacidade)
    
    def absorb(self, data):
        # Absorve os dados em blocos do tamanho do rate
        for i in range(0, len(data), self.rate):
            block = data[i:i+self.rate]
            # XOR do bloco com o estado atual
            for j in range(len(block)):
                self.state[j] ^= block[j]
            # Aplica a permutação (simulada via SHAKE-256)
            self._permute()
    
    def _permute(self):
        # Usa KeccakHash para simular a permutação Keccak-f
        keccak = KeccakHash(rate=self.rate, dsbyte=0x1f)
        keccak.absorb(self.state)
        self.state = bytearray(keccak.squeeze(len(self.state)))
    
    def squeeze(self, output_length):
        output = bytearray()
        # Gera a saída do tamanho desejado
        while len(output) < output_length:
            output.extend(self.state[:self.rate])
            self._permute()
        return output[:output_length]

def aead_shake_encrypt(plaintext, ad, key):
    # Cifração
    sponge_enc = SpongeSHAKE256()
    sponge_enc.absorb(key.encode() + ad.encode())  # Absorve chave e dados associados
    keystream = sponge_enc.squeeze(len(plaintext))  # Gera keystream do mesmo tamanho que o plaintext
    
    # Cifra o plaintext com XOR
    ciphertext = bytearray()
    for p, k in zip(plaintext.encode(), keystream):
        ciphertext.append(p ^ k)
    
    # Gera a tag (absorve o ciphertext e espreme a tag)
    sponge_tag = SpongeSHAKE256()
    sponge_tag.absorb(key.encode() + ad.encode() + ciphertext)
    tag = sponge_tag.squeeze(16)  # Tag de 16 bytes
    
    return {
        "ciphertext": ciphertext,
        "tag": tag
    }

def aead_shake_decrypt(ciphertext, ad, key, tag):
    # Verifica a tag primeiro
    sponge_tag = SpongeSHAKE256()
    sponge_tag.absorb(key.encode() + ad.encode() + ciphertext)
    computed_tag = sponge_tag.squeeze(16)
    
    if computed_tag != tag:
        raise ValueError("Autenticação falhou: tag inválida")
    
    # Decifra o ciphertext
    sponge_dec = SpongeSHAKE256()
    sponge_dec.absorb(key.encode() + ad.encode())
    keystream = sponge_dec.squeeze(len(ciphertext))
    
    plaintext = bytearray()
    for c, k in zip(ciphertext, keystream):
        plaintext.append(c ^ k)
    
    return plaintext.decode()

# Teste
def test_aead_shake():
    plaintext = "Mensagem secreta"
    ad = "Dados associados"
    key = "chave_secreta"

    # Cifração
    encrypted = aead_shake_encrypt(plaintext, ad, key)
    print("Ciphertext:", encrypted["ciphertext"])
    print("Tag:", encrypted["tag"])

    # Decifração
    decrypted = aead_shake_decrypt(encrypted["ciphertext"], ad, key, encrypted["tag"])
    print("Decrypted:", decrypted)

    assert decrypted == plaintext, "Erro: O texto decifrado não corresponde ao texto original"

    # Teste de integridade da tag
    try:
        aead_shake_decrypt(encrypted["ciphertext"], ad, key, encrypted["tag"][:-1] + b'\x00')
    except ValueError as e:
        print("Tag inválida detectada corretamente:", e)
    else:
        print("Erro: Tag inválida não foi detectada")

# if __name__ == "__main__":
#     test_aead_shake()
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os


def add_padding(plaintext, block_size):
    # 1. Temos que dar pad ao input para este ser multiplo de 128 bits, ou 16 bytes
    padder = padding.PKCS7(block_size * 8).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    return padded_data

def remove_padding(padded_data, block_size):
    # 1. Temos que remover o padding ao texto para obter o texto original
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    
    return plaintext

def remove_padding(padded_data, block_size):
    # Cria um objeto de unpadding com o tamanho do bloco (16 bytes para AES)
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    # Remove o padding do texto decifrado
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext

def tbc128_encrypt(key,tweak,plaintext):
    
    # 1. Adicionar padding ao plaintext
    block_size = 16
    padded_plaintext = add_padding(plaintext, block_size)
    
    # 2. Abordagem usada nas cifras "lighweight"
    # A vantagem da tweaked key é que vai estar associada a cada bloco, adicionando um critério de autenticidade
    tweaked_key = key + tweak
    
    # 3. Inicializar a cifra
    # Ainda nao percebi bem se devemos usar o modo ECB ou CBC, mas o CBC é mais seguro
    cipher = Cipher(algorithms.AES(tweaked_key), modes.ECB())
    encryptor = cipher.encryptor()
    
    # 4. Cifrar o plaintext
    # O finalize não é extritamente necessário, mas é boa prática
    ciphertext = encryptor.update(padded_plaintext) 
    
    print("ciphertext:",ciphertext)
    return ciphertext
    
    
def tbc128_decrypt(key,tweak,ciphertext):
    # Processo inverso usado anteriormente para cifrar o texto
    tweaked_key = key + tweak
    
    cipher = Cipher(algorithms.AES(tweaked_key), modes.ECB())
    decryptor = cipher.decryptor()
    
    # Decifra o texto cifrado
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    block_size = 16 
    plaintext = remove_padding(padded_plaintext, block_size)
    
    print("Plaintext:", plaintext)
    return plaintext


plaintext = b"Hello World"
key = os.urandom(16)
tweak = os.urandom(16)
cipher = tbc128_encrypt(key,tweak,plaintext)
decipher = tbc128_decrypt(key,tweak,cipher)
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os

def derive_key(key, tweak):
    input_key_material = key + tweak

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=16,  # change if needed
        salt=None,
        info=b'tbc128_encrypt'
    )
    tkey = hkdf.derive(input_key_material)
    
    return tkey


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


def tbc128_encrypt(key,tweak,plaintext):
    
    # 1. Abordagem usada nas cifras "lighweight"
    # A vantagem da tweaked key é que vai estar associada a cada bloco, adicionando um critério de autenticidade
    #tweaked_key = key + tweak
    derived_key = derive_key(key, tweak)
    
    # 2. Inicializar a cifra
    # Ainda nao percebi bem se devemos usar o modo ECB ou CBC, mas o CBC é mais seguro
    cipher = Cipher(algorithms.AES(derived_key), modes.ECB())
    encryptor = cipher.encryptor() 

    # 3. Cifrar o plaintext
    # O finalize não é extritamente necessário, mas é boa prática
    ciphertext = encryptor.update(plaintext) 

    #print("ciphertext:",ciphertext)
    return ciphertext
    
    
def tbc128_decrypt(key,tweak,ciphertext):
    # Processo inverso usado anteriormente para cifrar o texto
    #tweaked_key = key + tweak
    derived_key = derive_key(key, tweak)
    
    cipher = Cipher(algorithms.AES(derived_key), modes.ECB())
    decryptor = cipher.decryptor() 
    
    # Decifra o texto cifrado
    plaintext = decryptor.update(ciphertext) 
    
    
    #print("Plaintext:", plaintext)
    return plaintext


#########################
#### Teste do código ####
#########################

# plaintext = b"Hello World"
# key = os.urandom(16)
# tweak = os.urandom(16)
# cipher = tbc128_encrypt(key,tweak,plaintext)
# decipher = tbc128_decrypt(key,tweak,cipher)
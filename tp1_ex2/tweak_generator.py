import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os


def tweak_generator(plaintext, nonce, auth):
    # 1. Existem dois tipos de tweaks: wi e w*
    wi = []  
    w_auth = None  

    # 2. Tamanho do bloco AES (16 bytes)
    block_size = 16

    # 3. Divide o plaintext em blocos
    blocks = [plaintext[i:i+block_size] for i in range(0, len(plaintext), block_size)]
    num_blocks = len(blocks)

    # 4. Gera os tweaks da cifra (wi)
    if auth == 0:
        for i in range(num_blocks):
            # Nounce ocupa os primeiros 8 bytes (64 bits)
            tweak = nonce
            # Counter ocupa os próximos 8 bytes (64 bits)
            tweak += i.to_bytes(8, 'big')
            # Bit final = 0 para tweaks da cifra
            tweak += b'\x00'
            wi.append(tweak)
        return wi

    # 5. Gera o tweak de autenticação (w*)
    elif auth == 1:
        # Nonce ocupa os primeiros 8 bytes (64 bits)
        tweak = nonce
        # Comprimento do texto claro ocupa os próximos 8 bytes (64 bits)
        tweak += len(plaintext).to_bytes(8, 'big')
        # Bit final = 1 para tweak da autenticação
        tweak += b'\x01'
        w_auth = tweak
        return w_auth
    
    
    
    
#######################
#######################
## Teste dos tweaks  ##
#######################
#######################

# # Texto claro para teste
# plaintext = b"Hello, World! This is a test message."

# # Nonce (8 bytes)
# nonce = os.urandom(8)

# # Gera os tweaks de cifração (wi)
# wi = tweak_generator(plaintext, nonce, auth=0)
# print("Tweaks de cifração (wi):")
# for i, tweak in enumerate(wi):
#     print(f"w{i}: {tweak.hex()}")  # Exibe o tweak em formato hexadecimal

# # Gera o tweak de autenticação (w*)
# w_auth = tweak_generator(plaintext, nonce, auth=1)
# print("\nTweak de autenticação (w*):", w_auth.hex())  # Exibe o tweak em formato hexadecimal
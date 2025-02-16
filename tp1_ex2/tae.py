import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
from tbc import tbc128_encrypt, tbc128_decrypt, add_padding, remove_padding
from tweak_generator import tweak_generator


def tae_encrypt(key,nounce,plaintext,ad):
    
    # A. Os primeiros Pi tbc usando a mesma chave, mas tweaks diferentes
    # B. O ultimo bloco Pm é cifrado fazendo um XOR de uma máscara gerada cifrando t
         # Nota -> t é o numero de bits do ultimo bloco
    # C. O ultimo passo é gerar o tag que é a paridade do plaintext
    
    block_size = 16
 
    #1. Dar pad à mensagem
    padded_plaintext = add_padding(plaintext, block_size)
    
    print("------------------------------------")
    print("Dividing the plaintext into blocks...")
    plaintext_blocks = [padded_plaintext[i:i+block_size] for i in range(0, len(padded_plaintext), block_size)]

    #2. Gerar os tweaks
    print("------------------------------------")
    print("Generating tweaks to encrypt the message...")
    wi = tweak_generator(padded_plaintext, nounce, auth=0)
    print("Tweaks generated.")
    
    #3. Cifrar os primeiros m blocos
        #Nota -> usamos 1 unica chaves mas tweaks diferentes
    print("------------------------------------")
    print("Encrypting the first m-1 blocks...")
    ciphertext_blocks = []
    for i, block in enumerate(plaintext_blocks[:-1]):
        ciphertext_block = tbc128_encrypt(key, wi[i], block)
        ciphertext_blocks.append(ciphertext_block)
    print("First m-1 blocks encrypted.")
    
    #4. Cifrar o ultimo bloco (pm)
        #Selecionar o ultimo bloco e calcular o seu tamanho, já que este tem que ser cifrado
    print("------------------------------------")
    print("Encrypting tau and the last block ...")
    last_block = plaintext_blocks[-1]
    tau = len(last_block).to_bytes(block_size, 'big')
        #Encriptar tau
    mask = tbc128_encrypt(key, wi[-1], tau)
        #Fazer XOR com o ultimo bloco
    pm_cipher = bytes([mask[i] ^ last_block[i] for i in range(len(last_block))])
    ciphertext_blocks.append(pm_cipher)
    print("Tau and the last block encrypted.")

    
    
    #5. Obter cypertext
    print("------------------------------------")
    print("Ciphertext Obtained:")
    ciphertext = b''.join(ciphertext_blocks)
    print(ciphertext.hex())
    
    
    #6. Gerar o tag
        #Calcular paridade
    print("------------------------------------")
    print("Calculating the parity to generate the tag...")
    parity = 0
    for byte in padded_plaintext:
        parity ^= byte
    parity = parity.to_bytes(16, 'big')
    print("Parity calculated.")
    print("Parity: ",parity.hex())
        #Gerar o tweak de autenticação
    w_auth = tweak_generator(padded_plaintext, nounce, auth=1) 
        #Cifrar a paridade
    print("Auth tweak generated.")
    print("Auth tweak: ",w_auth.hex())
    tag = tbc128_encrypt(key, w_auth, parity)  # Cifra a paridade para gerar a tag
    print(f"Obtained tag: {tag.hex()}")

    
    return ciphertext, tag
    
    
def tae_decrypt(key, nonce, ciphertext, associated_data, tag):
    block_size = 16  # Tamanho do bloco AES (16 bytes)

    # 1. Divide o texto cifrado em blocos
    print("------------------------------------")
    print("Dividing the ciphertext into blocks...")
    ciphertext_blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    num_blocks = len(ciphertext_blocks)

    # 2. Gera os tweaks de decifração (wi) com base no texto cifrado
    print("------------------------------------")
    print("Generating tweaks to decrypt the message...")
    wi = tweak_generator(ciphertext, nonce, auth=0)

    # 3. Decifra os primeiros m-1 blocos
    print("------------------------------------")
    print("Decrypting the first m-1 blocks...")
    plaintext_blocks = []
    for i, block in enumerate(ciphertext_blocks[:-1]):  # Todos os blocos, exceto o último
        plaintext_block = tbc128_decrypt(key, wi[i], block)
        plaintext_blocks.append(plaintext_block)
    
    # 4. Decifra o último bloco de forma distinta
    print("------------------------------------")
    print("Decrypting tau and the last block...")
    last_block_ciphertext = ciphertext_blocks[-1]
    tau = len(last_block_ciphertext).to_bytes(block_size, 'big')  # τ é o tamanho do último bloco (em bytes)
    mask = tbc128_encrypt(key, wi[-1], tau)  # Gera a máscara cifrando τ
    last_block_plaintext = bytes([last_block_ciphertext[j] ^ mask[j] for j in range(len(last_block_ciphertext))])  # XOR com a máscara
    plaintext_blocks.append(last_block_plaintext)

    # 5. Concatena os blocos decifrados para formar o texto claro final (com padding)
    padded_plaintext = b''.join(plaintext_blocks)

    # 6. Remove o padding do texto claro
    plaintext = remove_padding(padded_plaintext, block_size)

    # 7. Verifica a tag de autenticação
    # Calcula a paridade do plaintext com padding
    print("------------------------------------")
    print("Calculating the parity to verify the tag...")
    parity = 0
    for byte in padded_plaintext:
        parity = parity ^ byte
    parity = parity.to_bytes(16, 'big') 

    # Gera o tweak de autenticação (w*)
    print("Generating the authentication tweak...")
    w_auth = tweak_generator(padded_plaintext, nonce, auth=1)

    # Cifra a paridade para gerar a tag esperada
    print("Calculating the expected tag...")
    expected_tag = tbc128_encrypt(key, w_auth, parity)

    # Compara a tag fornecida com a tag esperada
    if tag != expected_tag:
        raise ValueError("Autenticação falhou: tag inválida")
    
    elif tag == expected_tag:
        print("Tag verified.")
    print("------------------------------------")
    
    return plaintext
    
    
    
# Chave AES-128 (16 bytes)
key = os.urandom(16)

# Nonce (8 bytes)
nounce = os.urandom(8)

# Plaintext
plaintext = b"Hello, World! This is a test message."

# Dados associados (não cifrados, mas autenticados)
associated_data = b"Metadados importantes"

# Cifrar o texto claro
ciphertext, tag = tae_encrypt(key, nounce, plaintext, associated_data)

# Decifrar o texto cifrado
try:
    decrypted_plaintext = tae_decrypt(key, nounce, ciphertext, associated_data, tag)
    print(f"Decrypted Plaintext: {decrypted_plaintext.decode()}")
except ValueError as e:
    print(e)



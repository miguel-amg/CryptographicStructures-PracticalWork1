import os
from tae import tae_encrypt, tae_decrypt

# Chave AES-128 (16 bytes)
key = os.urandom(16)

# Nonce (8 bytes)
nounce = os.urandom(8)

# Plaintext
plaintext = b"Hello, World! This is a test message."
print("plaintext:", plaintext)
# Dados associados (não cifrados, mas autenticados)
associated_data = b"Metadados importantes"

# Cifrar o texto claro
ciphertext, tag = tae_encrypt(key, nounce, plaintext, associated_data)
print("ciphertext:", ciphertext)
print("tag:", tag)

# Decifrar o texto cifrado
try:
    decrypted_plaintext = tae_decrypt(key, nounce, ciphertext, associated_data, tag)
    print("decrypted_plaintext:", decrypted_plaintext)
    # Aqui você pode adicionar código para verificar se o texto decifrado é igual ao texto original
    assert decrypted_plaintext == plaintext, "O texto decifrado não corresponde ao texto original"
except ValueError as e:
    # Aqui você pode adicionar código para lidar com a falha de autenticação
    pass
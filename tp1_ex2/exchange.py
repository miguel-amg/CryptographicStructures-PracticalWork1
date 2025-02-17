from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from tae import tae_encrypt, tae_decrypt
import os
from channelUtils import generate_x25519_key_pair, generate_ed25519_key_pair, derive_shared_key, sign_data, verify_signature, hkdf_derive_key

def key_exchange_and_authentication():
    """Simula a troca de chaves e autenticação entre dois agentes."""
    # Agente A gera seus pares de chaves
    a_x25519_private, a_x25519_public = generate_x25519_key_pair()
    a_ed25519_private, a_ed25519_public = generate_ed25519_key_pair()

    # Agente B gera seus pares de chaves
    b_x25519_private, b_x25519_public = generate_x25519_key_pair()
    b_ed25519_private, b_ed25519_public = generate_ed25519_key_pair()

    # Agente A envia sua chave pública X25519 e assina com Ed25519
    a_signed_public_key = sign_data(a_ed25519_private, a_x25519_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))

    # Agente B verifica a assinatura de A
    if not verify_signature(a_ed25519_public, a_signed_public_key, a_x25519_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )):
        raise ValueError("Assinatura de A inválida!")

    # Agente B envia sua chave pública X25519 e assina com Ed25519
    b_signed_public_key = sign_data(b_ed25519_private, b_x25519_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))

    # Agente A verifica a assinatura de B
    if not verify_signature(b_ed25519_public, b_signed_public_key, b_x25519_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )):
        raise ValueError("Assinatura de B inválida!")

    # Agente A deriva a chave compartilhada
    a_shared_key = derive_shared_key(a_x25519_private, b_x25519_public)
    a_derived_key = hkdf_derive_key(a_shared_key)

    # Agente B deriva a chave compartilhada
    b_shared_key = derive_shared_key(b_x25519_private, a_x25519_public)
    b_derived_key = hkdf_derive_key(b_shared_key)

    # Confirmação da chave acordada
    if a_derived_key != b_derived_key:
        raise ValueError("As chaves derivadas não coincidem!")
    else:
        print("Chave compartilhada confirmada com sucesso!")

    return a_derived_key, b_derived_key



# Simulação da troca de chaves e autenticação
a_key, b_key = key_exchange_and_authentication()

# Mensagem a ser enviada
plaintext = b"Hello, World! This is a test message."

nonce = os.urandom(8)
associated_data = b"Metadados importantes"

# Agente A cifra a mensagem
ciphertext, tag = tae_encrypt(a_key, nonce, plaintext, associated_data)

# Agente B decifra a mensagem
decrypted_plaintext = tae_decrypt(b_key, nonce, ciphertext, associated_data, tag)

print(f"Mensagem decifrada: {decrypted_plaintext.decode()}")
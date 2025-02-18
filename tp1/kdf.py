# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Imports
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Função que cria deriva uma chave utilizando o algoritmo HKDF com hash SHA256
def derive_key(master_key: bytes, length: int, salt: bytes, info: bytes) -> bytes:
    # Verificações
    if not master_key:
        raise ValueError("A chave não pode estar vazia.")
    if not salt:
        raise ValueError("O salt não pode estar vazio.")
    if not info:
        raise ValueError("O info não pode estar vazio.")

    # Advertir caso a chave seja demasiado pequena
    if len(master_key) < 16:
        print("[KDF] Aviso: A chave tem menos de 16 bytes. Entropia insuficiente para derivar uma chave segura.")

    # O HKDF já estende a chave de forma determinística para o tamanho desejado
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(master_key)
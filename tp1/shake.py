# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Imports
import sys
from cryptography.hazmat.primitives import hashes

# Instancia do shake256 em modo XOFHash (que permite obter um output de tamanho variavel)
# O tamamho maximo possivel do output foi definido para o maximo do sistema
digest = hashes.Hash(hashes.SHAKE256(digest_size=100))
digest.update(b"abc") # Adicionar para passar para bytes
digest.finalize()
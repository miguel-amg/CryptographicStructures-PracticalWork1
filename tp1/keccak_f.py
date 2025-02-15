import numpy as np

# Constantes de rotação (r[x,y])
RHO_OFFSETS = np.array([
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14]
])

# Constantes de rodada RC[i]
ROUND_CONSTANTS = np.array([
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
], dtype=np.uint64)

def rot(value, shift):
    """Rotação circular à esquerda para valores de 64 bits."""
    return ((value << shift) & 0xFFFFFFFFFFFFFFFF) | (value >> (64 - shift))

def keccak_f(state):
    """Aplica a permutação Keccak-f[1600] ao estado fornecido."""
    # Converte o estado em uma matriz 5x5 de palavras de 64 bits
    A = np.array(state, dtype=np.uint64).reshape(5, 5)

    # Executa 24 rodadas
    for round_idx in range(24):
        # Passo θ
        C = A[:, 0] ^ A[:, 1] ^ A[:, 2] ^ A[:, 3] ^ A[:, 4]
        D = np.roll(C, -1) ^ np.roll(C, 1, axis=0)
        A ^= D[:, None]

        # Passos ρ e π
        B = np.zeros_like(A)
        for x in range(5):
            for y in range(5):
                B[y, (2*x + 3*y) % 5] = rot(A[x, y], RHO_OFFSETS[x, y])
        
        # Passo χ
        for x in range(5):
            for y in range(5):
                A[x, y] = B[x, y] ^ ((~B[(x+1) % 5, y]) & B[(x+2) % 5, y])

        # Passo ι
        A[0, 0] ^= ROUND_CONSTANTS[round_idx]

    return A.flatten().tolist()

# Teste com estado inicial zerado
test_state = [0] * 25
new_state = keccak_f(test_state)
print("Novo estado após Keccak-f[1600]:", new_state)
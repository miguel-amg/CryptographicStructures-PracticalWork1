import numpy as np

def test_keccak_f():
    """Teste para a função keccak_f."""
    test_state = [0] * 25  # Estado inicial zerado
    expected_length = 25  # O estado deve permanecer com 25 elementos
    
    try:
        new_state = keccak_f(test_state)
        assert len(new_state) == expected_length, "Erro: O estado de saída tem tamanho incorreto."
        assert isinstance(new_state, list), "Erro: O estado de saída deve ser uma lista."
        print("Teste bem-sucedido: keccak_f gera um estado de saída válido.")
    except Exception as e:
        print(f"Teste falhou: {e}")

RHO_OFFSETS = np.array([
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14]
], dtype=np.uint64)

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
    shift = np.uint64(shift)  # Garante que o shift seja tratado corretamente como uint64
    value = np.uint64(value)  # Garante que value seja tratado corretamente como uint64
    return ((value << shift) & np.uint64(0xFFFFFFFFFFFFFFFF)) | (value >> np.uint64(64 - shift))

def keccak_f(state):
    """Aplica a permutação Keccak-f[1600] ao estado fornecido."""
    A = np.array(state, dtype=np.uint64).reshape(5, 5)

    for round_idx in range(24):
        # Passo θ
        C = A[:, 0] ^ A[:, 1] ^ A[:, 2] ^ A[:, 3] ^ A[:, 4]
        D = np.roll(C, -1) ^ np.roll(C, 1, axis=0)
        A ^= D[:, None]

        # Passos ρ e π
        B = np.zeros_like(A, dtype=np.uint64)
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

# Executar o teste
test_keccak_f()

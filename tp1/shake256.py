import keccak

# Teste com estado inicial zerado
test_state = [0] * 25
new_state = keccak.keccak_f(test_state)
print("Novo estado após Keccak-f[1600]:", new_state)
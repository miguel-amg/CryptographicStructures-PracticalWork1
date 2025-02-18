import os
from tweak_generator import tweak_generator

# ######################
# ######################
# # Teste dos tweaks  ##
# ######################
# ######################

# Texto claro para teste
plaintext = b"Hello, World! This is a test message."

# Nonce (8 bytes)
nonce = os.urandom(8)

# Gera os tweaks de cifração (wi)
wi = tweak_generator(plaintext, nonce, auth=0)
print("Tweaks de cifração (wi):")
for i, tweak in enumerate(wi):
    print(f"w{i}: {tweak.hex()}")  # Exibe o tweak em formato hexadecimal

# Gera o tweak de autenticação (w*)
w_auth = tweak_generator(plaintext, nonce, auth=1)
print("\nTweak de autenticação (w*):", w_auth.hex())  # Exibe o tweak em formato hexadecimal
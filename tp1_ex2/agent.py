from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from tae import tae_encrypt, tae_decrypt
import os
from channelUtils import generate_x25519_key_pair, generate_ed25519_key_pair, derive_shared_key, sign_data, verify_signature, hkdf_derive_key, parse_arguments
import socket
import threading


def agent(role):
    
    # criar as chaves
    x25519_private, x25519_public = generate_x25519_key_pair()
    ed25519_private, ed25519_public = generate_ed25519_key_pair()

    if role == "receiver":
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('localhost', 12345))
        server_socket.listen(1)
        print("À espera de conexões...")
        client_socket, addr = server_socket.accept()
        print(f"Conexão estabelecida com {addr}.")
    else:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 12345))
        print("Conectado com B.")

    # estamos a usar interfaces do cryptography para serializar as chaves
    x25519_public_bytes = x25519_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    ed25519_public_bytes = ed25519_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    signed_public_key = sign_data(ed25519_private, x25519_public_bytes) #assinar a chave publica x25519
    
    # print(f"{role}: Enviando chave pública X25519: {x25519_public_bytes.hex()}")
    # print(f"{role}: Enviando chave pública Ed25519: {ed25519_public_bytes.hex()}")
    # print(f"{role}: Enviando assinatura: {signed_public_key.hex()}")
    
    print("A enviar chaves públicas e assinatura...")
    client_socket.send(x25519_public_bytes)
    client_socket.send(ed25519_public_bytes)
    client_socket.send(signed_public_key)

    # Recebe a chave pública X25519, a chave pública Ed25519 e a assinatura do outro agente
    peer_x25519_public_bytes = client_socket.recv(32)
    peer_ed25519_public_bytes = client_socket.recv(32)
    peer_signature = client_socket.recv(64)
    # print(f"{role}: Recebida chave pública X25519 do outro agente: {peer_x25519_public_bytes.hex()}")
    # print(f"{role}: Recebida chave pública Ed25519 do outro agente: {peer_ed25519_public_bytes.hex()}")
    # print(f"{role}: Recebida assinatura do outro agente: {peer_signature.hex()}")

    # Verifica a assinatura do outro agente
    peer_x25519_public = X25519PublicKey.from_public_bytes(peer_x25519_public_bytes)
    peer_ed25519_public = Ed25519PublicKey.from_public_bytes(peer_ed25519_public_bytes)
    
    if not verify_signature(peer_ed25519_public, peer_signature, peer_x25519_public_bytes):
        print(f"{role}: Assinatura inválida! Dados recebidos:")
        print(f"Chave pública X25519: {peer_x25519_public_bytes.hex()}")
        print(f"Chave pública Ed25519: {peer_ed25519_public_bytes.hex()}")
        print(f"Assinatura: {peer_signature.hex()}")
        raise ValueError("Assinatura do outro agente inválida!")
    else:
        print(f"{role}: Assinatura verificada com sucesso!")

    # Deriva a chave compartilhada
    shared_key = derive_shared_key(x25519_private, peer_x25519_public)
    derived_key = hkdf_derive_key(shared_key)
    print(f"{role}: Chave compartilhada calculada: {derived_key.hex()}")

    def receive_messages():
        while True:
            ciphertext = client_socket.recv(1024)
            if not ciphertext:
                break
            nonce = client_socket.recv(8)
            tag = client_socket.recv(16)
            associated_data = b"Dados associados"

            plaintext = tae_decrypt(derived_key, nonce, ciphertext, associated_data, tag)
            print("\n")
            print(f"Mensagem recebida: {plaintext.decode()}")
            print("Envia uma mensagem: ")
            

    def send_messages():
        while True:
            
            message = input(f"Envia uma mensagem: ")
            nonce = os.urandom(8)
            associated_data = b"Dados associados"
            ciphertext, tag = tae_encrypt(derived_key, nonce, message.encode(), associated_data)

            client_socket.send(ciphertext)
            client_socket.send(nonce)
            client_socket.send(tag)

    # Inicia threads para enviar e receber mensagens
    threading.Thread(target=receive_messages).start()
    threading.Thread(target=send_messages).start()
    
    
    
def main():
    args = parse_arguments()
    agent(args.role)

if __name__ == "__main__":
    main()
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from tae import tae_encrypt, tae_decrypt, add_padding, remove_padding
import os
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description="Agente para comunicação segura.")
    parser.add_argument(
        "-r", "--role",
        required=True,
        choices=["emitter", "receiver"],
        help="Papel do agente: 'emitter' ou 'receiver'."
    )
    return parser.parse_args()

#Vamos usar X25519 para troca de chaves 
#Vamos usar Ed25519 para assinatura/autenticacao de chaves


def generate_x25519_key_pair(): # usado na troca de chaves
    private_key = X25519PrivateKey.generate() # chave utilizada para derivar uma chave publica através de um a
    public_key = private_key.public_key() # chave que será partilhada para o espaço publico 
    # quando combinada com a chave do recetor permite derivar uma chave partilhada
    return private_key, public_key

def generate_ed25519_key_pair(): #usado na autenticacao
    private_key = Ed25519PrivateKey.generate() # cria uma assinatura digital de um conjunto de dados
    public_key = private_key.public_key() #verifica a autenticidade da assinatura
    return private_key, public_key

def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key) # cria a chave partilhada
    # esta chave é igual para ambos os agentes
    return shared_key

def sign_data(private_key, data):    # assina os dados
    signature = private_key.sign(data) 
    return signature

def verify_signature(public_key, signature, data):# verifica a assinatura
    try:
        public_key.verify(signature, data)
        return True
    except:
        return False

def hkdf_derive_key(shared_key, salt=None, info=b"key_derivation"):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_key)





# Cryptographic Structures - Practical Work #1

## Use the *'cryptography'* package to create a private asynchronous communication between an Emitter agent and a Receiver agent that covers the following aspects:
1. Client-server communication using the python package *'asyncio'*.
2. Use the SHAKE-256 hash in XOFHash mode as a AEAD (authenticated) cipher.
3. The cipher keys and nounces are generated by a KDF generator. The different keys for KDF initialization are given as inputs for the emitter and the receiver.
   
## Use the *cryptography package* to
1. Implement an AEAD with “Tweakable Block Ciphers” as described in the last section of the *'Chapter 1: Basic Cryptographic Primitives'*. The primitive block cipher used to generate the “tweakable block cipher” is AES-128.
2. Use this cipher to build a private asynchronous information channel with key agreement made with “X25519 key exchange” and “Ed25519 Signing&Verification” for agent authentication. It must include the confirmation of the agreed key.

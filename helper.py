from rsa_code import *
from Crypto import Random

def createKeys():
    privateKey = generate_key_str()
    publicKey = public_key_str(privateKey)
    symmetricKeyEncrypted = encrypt(Random.get_random_bytes(24), publicKey)
    return {
        'privateKey': privateKey,
        'publicKey': publicKey,
        'symmetricKeyEncrypted': symmetricKeyEncrypted
    }
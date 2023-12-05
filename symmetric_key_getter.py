from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import sys
import os
if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as fpPrivateKey:
        privateKey = fpPrivateKey.read()
        print('this is privateKey')
        print(privateKey)
        with open(sys.argv[2], 'rb') as fpSymmetricKeyEncrypted:
            symmetricKey = fpSymmetricKeyEncrypted.read()
            print("this is symmetric key")
            print(symmetricKey)
    private_key_obj = RSA.import_key(privateKey)
    decrypt_cipher = PKCS1_OAEP.new(private_key_obj)
    decrypted_text = decrypt_cipher.decrypt(symmetricKey)
    with open(f'{os.getcwd()}/symmetricKey.aes', 'wb') as fp:
        fp.write(decrypted_text)

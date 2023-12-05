from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import os.path
from os import listdir
from os.path import isfile, join
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import padding
import base64
import sys
import os

if __name__ == '__main__':
    
    with open(sys.argv[1], 'rb') as fpSymmetricKey:
        symmetricKey = fpSymmetricKey.read()
        with open(sys.argv[2], 'rb') as fpEncryptedFile:
            encryptedFile = fpEncryptedFile.read()

    try:
        # Ensure that the string length is a multiple of 4 by adding padding characters
        while len(encryptedFile) % 4 != 0:
            encryptedFile += '='

        # Decode base64
        iv_and_data = base64.b64decode(encryptedFile)
        # Extract IV and encrypted data
        iv = iv_and_data[:8]
        encrypted_data = iv_and_data[8:]
    
        # Create a TripleDES cipher in CBC mode
        cipher = Cipher(algorithms.TripleDES(symmetricKey), modes.CBC(iv), backend=default_backend())

        # Decrypt the data
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove the padding
        unpadder = PKCS7(64).unpadder()  # Use the same block size (64) as during encryption
        original_data = unpadder.update(decrypted_data) + unpadder.finalize()
        
        with open(f'{os.getcwd()}/decrypted', 'wb') as fp:
            fp.write(original_data)
    except Exception as e:
        print({"error": str(e)})
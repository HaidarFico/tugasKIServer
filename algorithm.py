# AES

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

class AESEncryptor:
    def __init__(self, key: str):
        if len(key) == 16:
            self.key_length = 16
        elif len(key) == 24:
            self.key_length = 24
        elif len(key) == 32:
            self.key_length = 32
        else:
            raise Exception("Key Length invalid.")
        self.key = key.encode('ASCII')
        self.iv = Random.new().read(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        
    def encrypt(self, message: str):
        plaintext = message
        ciphertext = self.cipher.encrypt(pad(plaintext, AES.block_size))
        return self.iv + ciphertext
    
    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plainttext = fo.read()
        enc = self.encrypt(plainttext)
        with open (file_name+'.enc', 'wb') as fo:
            fo.write(enc)
        print(file_name)
        os.remove(file_name)

    def decrypt(self, cipherText):
        plainText = self.cipher.decrypt(cipherText)
        return plainText
    
    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            iv = fo.read(self.key_length)
            self.iv = iv
            self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext)
        plaintext = unpad(dec, AES.block_size)
        newFileDir = os.getcwd() + '/decrypt/' + 'temp'
        print(newFileDir)
        with open(newFileDir, 'wb') as fo:
            fo.write(plaintext)

    def getAllFiles(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        dirs = []
        for dirName, subDirList, fileList in os.walk(dir_path + '/files'):
            for fname in fileList:
                dirs.append(dirName+"\\"+fname)
        return dirs
    
    def encrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.encrypt_file(file_name)

    def decrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.decrypt_file(file_name)
           

# RC4

from Crypto.Cipher import ARC4
import hashlib
import time
import getpass
import datetime

# preparing the file name after being decrypted
def pre_encrypt(input_file, key):
    # Separate the file name and extension
    base_name, file_extension = input_file.rsplit('.', 1)
    # Generate a timestamp
    # Append e (encrypted) and timestamp to the file name
    output_file = f"{base_name}.{file_extension}.enc"   
    # calling the encrypt function
    encrypt_file(input_file, output_file, key) 
  
# preparing the file name after being decrypted
def pre_decrypt(input_file, key):
    # Separate the file name and extension
    base_name, file_extension = input_file.rsplit('.', 1)
    # Generate a timestamp
    # Append d (encrypted) and timestamp to the file name
    output_file = f"{base_name}.{file_extension}"   
    # calling the decrypt function
    decrypt_file(input_file, output_file, key) 

# function to encrypt
def encrypt_file(input_file, output_file, key):
    rc4 = ARC4.new(key.encode('ASCII'))
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        while True:
            chunk = infile.read(1024)
            if not chunk:
                break
            encrypted_chunk = rc4.encrypt(chunk)
            outfile.write(encrypted_chunk)

# function to decrypt
def decrypt_file(input_file, output_file, key):
    rc4 = ARC4.new(key.encode('ASCII'))
    print(input_file)
    print(output_file)
    newFileDir = os.getcwd() + '/decrypt/' + 'temp'

    print(newFileDir)
    with open(input_file, 'rb') as infile, open(newFileDir, 'wb') as outfile:
        while True:
            chunk = infile.read(1024)
            if not chunk:
                break
            decrypted_chunk = rc4.decrypt(chunk)
            outfile.write(decrypted_chunk)

def encrypt_data_cbc(data, iv, SECRET_KEY):
    data = data
    
    # Create a TripleDES cipher in CBC mode
    cipher = Cipher(algorithms.TripleDES(SECRET_KEY), modes.CBC(iv), backend=default_backend())
    
    # Encrypt the data
    encryptor = cipher.encryptor()
    padder = PKCS7(64).padder()  # 64 is the block size for TripleDES
    padded_data = padder.update(data) + padder.finalize()
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    
    # Combine IV and encrypted data and encode as base64
    iv_and_data = iv + cipher_text
    encrypted_data_base64 = base64.b64encode(iv_and_data).decode('utf-8')
    
    return encrypted_data_base64

def decrypt_data_cbc(data, SECRET_KEY):
    encrypted_data_base64 = data
    
    try:
        # Ensure that the string length is a multiple of 4 by adding padding characters
        while len(encrypted_data_base64) % 4 != 0:
            encrypted_data_base64 += '='

        # Decode base64
        iv_and_data = base64.b64decode(encrypted_data_base64.encode('utf-8'))
        # Extract IV and encrypted data
        iv = iv_and_data[:8]
        encrypted_data = iv_and_data[8:]
    
        # Create a TripleDES cipher in CBC mode
        cipher = Cipher(algorithms.TripleDES(SECRET_KEY), modes.CBC(iv), backend=default_backend())

        # Decrypt the data
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove the padding
        unpadder = PKCS7(64).unpadder()  # Use the same block size (64) as during encryption
        original_data = unpadder.update(decrypted_data) + unpadder.finalize()
        return original_data.decode()
    except Exception as e:
        return {"error": str(e)}
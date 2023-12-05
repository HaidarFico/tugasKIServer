from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import time
import getpass
import datetime

# Generate an RSA key pair
def generate_key_str():
    key = RSA.generate(2048)
    private_key_bytes = key.export_key()
    private_key_str = base64.b64encode(private_key_bytes).decode('utf-8') # string, can't be used directly
    
    # Extract public key
    public_key = key.publickey()
    public_key_bytes = public_key.export_key()
    public_key_str = base64.b64encode(public_key_bytes).decode('utf-8') # string, can't be used directly
    
    # Create a file to store private & public key
    timestamp = datetime.datetime.now().strftime("%H%M%S%d%m%y")
    file_name = 'keys' + timestamp + '.txt'
    with open(file_name, 'w') as file:
        file.write(f"Private Key:\n{private_key_str}\n\nPublic Key:\n{public_key_str}")
        
    # return the private key
    return private_key_str
    
# Extract public key
def public_key_str(private_key_str):
    key = base64.b64decode(private_key_str) # to bytes
    key_object = RSA.import_key(key) # to object
    public_key = key_object.publickey()
    public_key_bytes = public_key.export_key()
    public_key_str = base64.b64encode(public_key_bytes).decode('utf-8')
    #public_key_str = public_key_bytes.decode('utf-8')
    return public_key_str

# Encrypt using the public key
def encrypt(text, public_key_str):
    public_key_bytes = base64.b64decode(public_key_str) # convert string back to bytes
    public_key_obj = RSA.import_key(public_key_bytes) # convert bytes back to RSA object
    cipher = PKCS1_OAEP.new(public_key_obj) # create the PKCS1_OAEP cipher object
    ciphertext = cipher.encrypt(text)
    ciphertext_str = base64.b64encode(ciphertext).decode('utf-8') # convert to string so it can be sent
    return ciphertext_str   

def encrypt_bytes(text, public_key_bytes):
    public_key_obj = RSA.import_key(public_key_bytes) # convert bytes back to RSA object
    cipher = PKCS1_OAEP.new(public_key_obj) # create the PKCS1_OAEP cipher object
    ciphertext = cipher.encrypt(text)
    return ciphertext   

''' 
plaintext = b"Lorem ipsum dolor amet"
cipher = PKCS1_OAEP.new(public_key)
ciphertext = cipher.encrypt(plaintext)
encrypted_message_base64 = base64.b64encode(ciphertext).decode('utf-8')
encrypted_message_base64_2 = base64.b64decode(encrypted_message_base64)
''' 

# Decrypt using the private key
def decrypt(text, private_key_str):
    private_key_bytes = base64.b64decode(private_key_str)
    private_key_obj = RSA.import_key(private_key_bytes)
    decrypt_cipher = PKCS1_OAEP.new(private_key_obj)
    text_bytes = base64.b64decode(text)
    decrypted_text = decrypt_cipher.decrypt(text_bytes)
    decrypted_text_str = decrypted_text.decode('utf-8')
    return decrypted_text_str

def decrypt_bytes(bytes, private_key_bytes):
    private_key_obj = RSA.import_key(private_key_bytes)
    decrypt_cipher = PKCS1_OAEP.new(private_key_obj)
    decrypted_text = decrypt_cipher.decrypt(bytes)
    return decrypted_text

'''   
private_key = key
decrypt_cipher = PKCS1_OAEP.new(private_key)
decrypted_text = decrypt_cipher.decrypt(encrypted_message_base64_2)

print("")
print("Original Message:", plaintext.decode('utf-8'))
print("Encrypted Message:", encrypted_message_base64)
print("Decrypted Message:", decrypted_text.decode('utf-8'))

# Print the private key and public key
print("Private Key:")
print(private_key_str)

print("\nPublic Key:")
print(public_key_str)
'''

# New implementation
def generate_key():
    key = RSA.generate(2048)
    private_key_bytes = key.export_key()
    
    # Extract public key
    public_key = key.publickey()
    public_key_bytes = public_key.export_key()
        
    # return the private key
    return {'public_key': public_key_bytes, 'private_key': private_key_bytes}    
    
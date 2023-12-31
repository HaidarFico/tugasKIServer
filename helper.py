from rsa_code import *
from Crypto import Random

from email_sending import *
from algorithm import *

import os


def createKeys(secretKey):
    keyPairs = generate_key()
    privateKeyEncrypted = encrypt_data_cbc_file(keyPairs.get('private_key'), generateIV(), secretKey)
    publicKeyEncrypted = encrypt_data_cbc_file(keyPairs.get('public_key'), generateIV(), secretKey)
    symmetricKeyEncrypted = encrypt_bytes(Random.get_random_bytes(24), keyPairs.get('public_key'))

    return {
        'privateKey': privateKeyEncrypted,
        'publicKey': publicKeyEncrypted,
        'symmetricKeyEncrypted': symmetricKeyEncrypted
    }

def getFileExtension(fileName):
    splittedText = fileName.split('.')
    if len(splittedText) != 2:
        return None
    
    return splittedText[1]

def getFileName(fileName):
    splittedText = fileName.split('.')
    if len(splittedText) != 2:
        return None
    
    return splittedText[0]

def getAllFiles(fullFilePath: str):
    dirs = []
    for dirName, subDirList, fileList in os.walk(fullFilePath):
        dirs.append(fileList)
    print(fullFilePath)
    print(dirs)
    return dirs[0]

def generateIV():
    return Random.get_random_bytes(8)

def generateSymmetricKey():
    return Random.get_random_bytes(24)

def SendRequestAffirmationEmail(emailDest, symmetricKeyUser, publicKeySourceEncrypted, ownerPublicKey, fileRequestId, fileDataPath, fileDestFolder, appSecretKey):
    credentials = get_credentials()
    http = credentials.authorize(httplib2.Http())
    service = discovery.build('gmail', 'v1', http=http)
    
    newSymmetricKey = generateSymmetricKey()

    publicKeySource = decrypt_data_cbc_file(publicKeySourceEncrypted, appSecretKey)
    symmetricKeyEncrypted = encrypt_bytes(newSymmetricKey, publicKeySource)
    fileRequestWaitingFolderDataPath = f'{os.getcwd()}/{fileDestFolder}/{fileRequestId}'

    with open(fileDataPath, 'rb') as fp:
        data = fp.read()
        file_data, _, signatureAndId = data.rpartition(b'\n%%SIGNATURE%%\n')
        if len(file_data) == 0:
            dataDecrypted = decrypt_data_cbc_file(data, symmetricKeyUser)   
            dataEncrypted = encrypt_data_cbc_file(dataDecrypted, generateIV(), newSymmetricKey)
        else:
            signature, _, id = signatureAndId.rpartition(b'\n%%ID%%\n')
            decryptFile = decrypt_data_cbc_file(file_data, symmetricKeyUser)
            is_valid_signature = verify_signature(decryptFile, signature, ownerPublicKey)
            if not is_valid_signature:
                return "Signature verification failed", 400
            decrypted_with_signature = decryptFile + b'\n%%SIGNATURE%%\n' + signature + b'\n%%ID%%\n' + id
            dataEncrypted = encrypt_data_cbc_file(decrypted_with_signature, generateIV(), newSymmetricKey)

        with open(fileRequestWaitingFolderDataPath, 'wb') as wp:
            wp.write(dataEncrypted)

    # sending through email
    email_sender = "haidarficoi@gmail.com"
    email_recipient = emailDest
    email_subject = "Key"
    email_body = (f"The key is attached to the file, please decrypt it with your private key:\n")
    
    testMessage = CreateMessageWithFile(email_sender, email_recipient, email_subject, email_body, symmetricKeyEncrypted, 'symmetricKeyEncrypted.enc')
    
    SendMessage(service, 'me', testMessage)
    return
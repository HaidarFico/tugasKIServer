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
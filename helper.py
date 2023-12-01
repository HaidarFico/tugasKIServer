from rsa_code import *
from Crypto import Random
from email_sending import *
from algorithm import *

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

def sendEmail(emailDest, symmetricKeyUser, publicKeySource, fileId, fileDataPath):
    credentials = get_credentials()
    http = credentials.authorize(httplib2.Http())
    service = discovery.build('gmail', 'v1', http=http)
    
    newSymmetricKey = generateSymmetricKey()
    symmetricKeyEncrypted = encrypt(newSymmetricKey, publicKeySource)
    fileRequestWaitingFolderDataPath = f'{os.getcwd()}/file_request_waiting/{fileId}'

    with open(fileDataPath, 'rb') as fp:
        data = fp.read()
        dataDecrypted = decrypt_data_cbc_file(data, symmetricKeyUser)   
        dataEncrypted = encrypt_data_cbc_file(dataDecrypted, generateIV(), newSymmetricKey)
        with open(fileRequestWaitingFolderDataPath, 'wb') as wp:
            wp.write(dataEncrypted)

    # sending through email
    email_sender = "hafizhmufidd@gmail.com"
    email_recipient = emailDest
    email_subject = "Key"
    email_body = (f"The key is:\n" + symmetricKeyEncrypted)
    
    testMessage = CreateMessage(email_sender, email_recipient, email_subject, email_body)
    
    testSend = SendMessage(service, 'me', testMessage)
    return
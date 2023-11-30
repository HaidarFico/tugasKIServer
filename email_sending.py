import httplib2
import os
from httplib2 import Http
from rsa_code import *

from email.mime.text import MIMEText

import base64

from googleapiclient import discovery
import oauth2client
from oauth2client import client
from oauth2client import tools

try:
    import argparse
    flags = argparse.ArgumentParser(parents=[tools.argparser]).parse_args()
except ImportError:
    flags = None

#SCOPES = 'https://www.googleapis.com/'
""" below grants full access of the gmail """
SCOPES = 'https://mail.google.com'

""" below is the credentials.json for the application secrets"""
CLIENT_SECRET_FILE = 'credentials.json'
APPLICATION_NAME = 'Gmail API Quickstart'

from oauth2client import file as oauth2file

def get_credentials():
    """Gets valid user credentials from storage."""
    home_dir = os.path.expanduser('~')
    credential_dir = os.path.join(home_dir, '.credentials')
    if not os.path.exists(credential_dir):
        os.makedirs(credential_dir)
    credential_path = os.path.join(credential_dir, 'gmail-quickstart.json')

    store = oauth2file.Storage(credential_path)
    credentials = store.get()
    if not credentials or credentials.invalid:
        flow = client.flow_from_clientsecrets(CLIENT_SECRET_FILE, SCOPES)
        flow.user_agent = APPLICATION_NAME
        if flags:
            credentials = tools.run_flow(flow, store, flags)
        else:  # Needed only for compatibility with Python 2.6
            credentials = tools.run(flow, store)
        print(f'Storing credentials to ' + credential_path)
    return credentials

def CreateMessage(sender, to, subject, message_text):
  """Create a message for an email.

  Args:
    sender: Email address of the sender.
    to: Email address of the receiver.
    subject: The subject of the email message.
    message_text: The text of the email message.

  Returns:
    An object containing a base64 encoded email object.
  """
  message = MIMEText(message_text.decode('utf-8'))
  message['to'] = to
  message['from'] = sender
  message['subject'] = subject
  return {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')}

'''
testMessage = CreateMessage('@gmail.com', 
                            '@gmail.com', 
                            'Testing', 
                            b'I just wanna be your everything by Andy Gibb')
print("Test Message:", testMessage)
'''

def SendMessage(service, user_id, message):
  """Send an email message.

  Args:
    service: Authorized Gmail API service instance.
    user_id: User's email address. The special value "me"
    can be used to indicate the authenticated user.
    message: Message to be sent.

  Returns:
    Sent Message.
  """
  try:
    message = (service.users().messages().send(userId=user_id, body=message)
               .execute())
    print (f'Message Id: %s' % message['id'])
    return message
  except errors.HttpError:
    print (f'An error occurred: %s' % error)

def main():
    credentials = get_credentials()
    http = credentials.authorize(httplib2.Http())
    service = discovery.build('gmail', 'v1', http=http)
    
    # generate requesting user's private key
    key = generate_key_str();
    print("Private key (string form):\n");
    print(key)
    
    # generate requesting user's public key 
    public_key = public_key_str(key)
    print("Public key (string form):\n")
    print(public_key)
    
    # encrypt the symmetric key with requesting user's public key
    symmetric_key = b"Aston Martin DBS 1970" # bytes, if string will error can't concat str to bytes
    encrypted_key = encrypt(symmetric_key, public_key)
    print("Encrypted symm. key with public key:\n")
    print(encrypted_key)
    
    # decrypt the encrypted symmetric key with requesting user's private key
    decrypted_key = decrypt(encrypted_key, key)
    print("Decrypted symm. key with private key:\n")
    print(decrypted_key)
    
    # sending through email
    email_sender = "sh.g3nsh1nn3r+1@gmail.com"
    email_recipient = "sh.g3nsh1nn3r+2@gmail.com"
    email_subject = "Testing"
    email_body = (b"The key is:\n" + encrypted_key.encode('utf-8'))
    
    testMessage = CreateMessage(email_sender, email_recipient, email_subject, email_body)
    
    testSend = SendMessage(service, 'me', testMessage)
    

if __name__ == '__main__':
   main()
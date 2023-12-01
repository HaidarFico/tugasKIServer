from server import *
from algorithm import *
from flask import Flask, request, jsonify, json, request, send_file
from flask_mysqldb import MySQL
from cryptography.fernet import Fernet
import base64
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask_mysqldb import MySQL
from form import *
from init import *
import json
from Crypto import Random
from rsa_code import *
from helper import *

app = Flask(__name__)

# Configure MySQL
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'ki'


mysql = MySQL(app)

# Email Configuration for Gmail
email_config = {

}

def send_email(subject, body, to_email, encrypted_file, encrypted_symmetric_key):
    pass

# Function to load keys from the database
def load_keys(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT public_key, private_key, symmetric_key FROM user WHERE id = %s", (user_id,))
    keys = cur.fetchone()
    cur.close()
    return keys

# Function to load email from the database
def load_email_receiver(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT email FROM user WHERE id = %s", (user_id,))
    email = cur.fetchone()
    cur.close()
    return email

# Function to generate a new symmetric key
def generate_symmetric_key():
    key = Fernet.generate_key()
    while len(key) != 24:
        key = Fernet.generate_key()
    return key


@app.route('/request_access', methods=['POST'])
def request_access():
    # Assume the request data contains user A's information, file identifier, and user B's ID
    data = request.get_json()
    user_a_id = data['user_a_id']
    user_b_id = data['user_b_id']
    file_id = data['file_id']

    # Fetch user B's public key and symmetric key from the database
    connection = mysql.connection
    cursor = connection.cursor()

    user_b_data = load_keys(user_b_id)
    if not user_b_data:
        cursor.close()
        connection.close()
        return jsonify({'error': 'User B not found'}), 404
    
    user_a_data = load_keys(user_a_id)
    if not user_a_data:
        cursor.close()
        connection.close()
        return jsonify({'error': 'User A not found'}), 404

    # user_a_email = load_email_receiver(user_a_id)
    
    # Fetch the file content from the database based on the file identifier
    cursor.execute("SELECT filename, file_extension FROM files WHERE id = %s", (file_id,))
    file_data = cursor.fetchone()

    if not file_data:
        cursor.close()
        connection.close()
        return jsonify({'error': 'File not found'}), 404

    filename, file_extension = file_data  # Corrected unpacking

    print(f"Filename: {filename}, File extension: {file_extension}")

    public_key_b, private_key_b, symmetric_key_b = user_b_data
    public_key_a, private_key_a, symmetric_key_a = user_a_data

    # Decrypt the file using user B's symmetric key
    try:
        file_data_path = os.path.join(FILE_DATA_FILE_PATH, f'{filename}.{file_extension}')
        with open(file_data_path, "rb") as fo:
            encrypted_file = fo.read()
            real_symmetric_key = decrypt_bytes(symmetric_key_b, private_key_b)
            decrypted_file = decrypt_data_cbc_file(encrypted_file, real_symmetric_key)

    except Exception as e:
        print(f"Error during decryption: {e}")
        return jsonify({'error': 'Error during decryption'}), 500

    # Generate a new symmetric key for encrypting the file for user A
    new_symmetric_key = generate_symmetric_key()  

    data_to_encrypt = decrypted_file
    iv = os.urandom(8)

    # Encrypt the file with the new symmetric key
    encrypted_file_for_a = encrypt_data_cbc_file(data_to_encrypt, iv, new_symmetric_key)

    # Encrypt the new symmetric key with user A's public key
    encrypted_symmetric_key_for_a = encrypt_data_cbc(new_symmetric_key, getSymmetricKey(user_a_id, db))

    cursor.close()
    connection.close()

    # checkings
    print(encrypted_file_for_a)
    print(encrypted_symmetric_key_for_a)

    return jsonify({'message': 'File and key sent to User A successfully'})

if __name__ == '__main__':
    app.run(debug=True)
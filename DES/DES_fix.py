from flask import Flask, request, jsonify, send_from_directory, Response
import psycopg2
import os
from datetime import datetime
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import padding
from werkzeug.utils import secure_filename
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

# database connection
database = psycopg2.connect(

)

# encryption parameters
SECRET_KEY = os.urandom(24)  
ENCRYPTION_KEY = os.urandom(24)  

# directory to store uploaded files
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/create_user', methods=['POST'])
def create_user():
    try:
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        iv = os.urandom(8)

        # Encrypt each data and convert it to bytes
        encrypted_username = encrypt_data_cbc(username.encode('utf-8'), iv)
        encrypted_email = encrypt_data_cbc(email.encode('utf-8'), iv)
        encrypted_password = encrypt_data_cbc(password.encode('utf-8'), iv)

        # Insert data into the userss table
        cursor = database.cursor()
        cursor.execute("INSERT INTO userss (username, email, password, registration_date, iv) VALUES (%s, %s, %s, %s, %s) RETURNING user_id",
                       (encrypted_username, encrypted_email, encrypted_password, datetime.now(), iv))
        new_user_id = cursor.fetchone()[0]
        database.commit()
        cursor.close()

        return jsonify({"message": "User created successfully with user_id: " + str(new_user_id)})

    except Exception as e:
        return jsonify({"error": str(e)})

    
@app.route('/get_user_data/<user_id>', methods=['GET'])
def get_user_data(user_id):
    try:
        cursor = database.cursor()
        cursor.execute("SELECT username, email, password, iv FROM userss WHERE user_id = %s", (user_id,))
        result = cursor.fetchone()
        cursor.close()

        if result:
            username_bytes, email_bytes, password_bytes, iv_bytes = result

            decrypted_username = decrypt_data_cbc(username_bytes)
            decrypted_email = decrypt_data_cbc(email_bytes)
            decrypted_password = decrypt_data_cbc(password_bytes)

            return jsonify({
                "user_id": user_id,
                "username": decrypted_username,
                "email": decrypted_email,
                "password": decrypted_password
            })
            
        return jsonify({"error": "User not found."})

    except Exception as e:
        return jsonify({"error": str(e)})
    
def encrypt_data_cbc(data, iv):
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


def decrypt_data_cbc(data):
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

# files extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'xls', 'jpg', 'png', 'mp4', 'avi', 'jpeg', 'docx'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['POST'])
def upload_file():
    user_id = request.form.get('user_id')
    file = request.files['file']

    if file and allowed_file(file.filename):
        try:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{user_id}_{filename}')
            file.save(file_path)

            iv = os.urandom(8)

            # create a cipher object for DES in CBC mode with the IV
            cipher = Cipher(algorithms.TripleDES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            file_data = open(file_path, 'rb').read()

            # Apply PKCS7 padding to the file data
            padder = PKCS7(64).padder()
            padded_file_data = padder.update(file_data) + padder.finalize()

            # Encrypt the padded file data
            encrypted_file_data = encryptor.update(padded_file_data) + encryptor.finalize()

            # Store the encrypted data in a file
            encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{user_id}_{filename}.enc')
            with open(encrypted_file_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_file_data)

            cursor = database.cursor()
            cursor.execute("UPDATE userss SET file_name = %s, file_data = %s, iv = %s WHERE user_id = %s",
                           (filename, encrypted_file_data, iv, user_id))
            database.commit()
            cursor.close()

            return jsonify({"message": "File uploaded and encrypted successfully."})
        except Exception as e:
            return jsonify({"error": str(e)})
    return jsonify({"error": "Invalid or unsupported file format."})


@app.route('/get_decrypted/<user_id>/<filename>', methods=['GET'])
def get_decrypted(user_id, filename):
    try:
        cursor = database.cursor()
        cursor.execute("SELECT file_data, iv FROM userss WHERE user_id = %s AND file_name = %s", (user_id, filename))
        result = cursor.fetchone()
        cursor.close()

        if result:
            encrypted_file_data, iv = result
            # Decrypt the file using DES in CBC mode
            cipher = Cipher(algorithms.TripleDES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_file_data = decryptor.update(encrypted_file_data) + decryptor.finalize()

            # Unpad the decrypted data using PKCS7
            unpadder = PKCS7(64).unpadder()
            unpadded_data = unpadder.update(decrypted_file_data) + unpadder.finalize()

            # Create a response with the decrypted data
            response = Response(unpadded_data)
            response.headers["Content-Disposition"] = f"attachment; filename={filename}"
            return response

        return jsonify({"error": "File not found for the given user."})
    except Exception as e:
        return jsonify({"error": str(e)})


if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=True)

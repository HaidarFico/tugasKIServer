from flask import Flask, request, jsonify, send_from_directory, Response
import psycopg2
import os
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import padding
from werkzeug.utils import secure_filename

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

        # generate an Initialization Vector (IV) for this user
        iv = os.urandom(8) 

        backend = default_backend()

        # create an encryptor for each data
        username_encryptor = create_encryptor(ENCRYPTION_KEY, iv, backend)
        email_encryptor = create_encryptor(ENCRYPTION_KEY, iv, backend)
        password_encryptor = create_encryptor(ENCRYPTION_KEY, iv, backend)

        # encrypt each data
        encrypted_username = encrypt_data(username, username_encryptor)
        encrypted_email = encrypt_data(email, email_encryptor)
        encrypted_password = encrypt_data(password, password_encryptor)

        # insert data into the userss table
        cursor = database.cursor()
        cursor.execute("INSERT INTO userss (username, email, password, registration_date, iv) VALUES (%s, %s, %s, %s, %s) RETURNING user_id",
                       (encrypted_username, encrypted_email, encrypted_password, datetime.now(), iv))
        new_user_id = cursor.fetchone()[0]
        database.commit()
        cursor.close()

        return jsonify({"message": "User created successfully with user_id: " + str(new_user_id)})

    except Exception as e:
        return jsonify({"error": str(e)})

# function for encryptor
def create_encryptor(key, iv, backend):
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)
    return cipher.encryptor()

# function for decryptor
def encrypt_data(data, encryptor):
    padder = padding.PKCS7(64).padder()
    padded_data = padder.update(data.encode('utf-8')) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

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

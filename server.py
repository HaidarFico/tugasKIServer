from flask import Flask, json, jsonify, request, send_file, render_template, url_for, redirect
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_mysqldb import MySQL
from flask_sqlalchemy import SQLAlchemy
# from sqlalchemy import create_engine
# from sqlalchemy.orm import scoped_session, sessionmaker, declarative_base
from flask_wtf import FlaskForm
from algorithm import *
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from sqlalchemy.sql import func


api = Flask(__name__)
        
api.config['MYSQL_HOST'] = '127.0.0.1'
api.config['MYSQL_USER'] = 'root'
api.config['MYSQL_PASSWORD'] = 'change-me'
api.config['MYSQL_DB'] = 'KI'
api.config['MYSQL_PORT'] = 3306
# mysql = MySQL(api)
bcrypt = Bcrypt(api)
SECRET_KEY = os.urandom(24)  # Store this securely
ENCRYPTION_KEY = os.urandom(24)  # Use a secure key for encryption
api.config['UPLOAD_FOLDER'] = 'uploads'
api.config['SECRET_KEY'] = SECRET_KEY
api.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:change-me@127.0.0.1:3306/KI'

db = SQLAlchemy(api)
login_manager = LoginManager()
login_manager.init_app(api)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "password"})
    submit = SubmitField('Register')

    # def validate_username(self, username):
    #     print('temp')

    #     # existing_user_username = 
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "password"})
    submit = SubmitField('Login')


@api.route('/', methods=['GET'])
def home():
    return render_template('home.html')

@api.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@api.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # hashed_password = bcrypt.generate_password_hash(form.password.data)
        # cur = mysql.connection.cursor()
        # queryString = f"INSERT INTO user (username, password) VALUES ('{form.username.data}', '{hashed_password.decode('ASCII')}')"
        # print(queryString)
        # cur.execute(queryString)
        # # cur.commit()
        # mysql.connection.commit()
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        # return redirect(url_for('login'))
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@api.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@api.route('/test', methods=['GET'])
def test() -> json:
    return jsonify({
        "message": "Hello World"
    })

@api.route('/aes', methods=['POST', 'GET'])
def AESHandler() -> json:
    username = request.form['username']
    password = request.form['password']
    key = request.form['key']

    cur = mysql.connection.cursor()
    queryString = "SELECT password FROM user WHERE username = '" + username + "'"
    cur.execute(queryString)
    rv = cur.fetchall()
    if password != rv[0][0]:
        return jsonify(
            {
                "message": "invalid username or password"
            }
        )

    if request.method == 'POST':
        f = request.files['file']
        filePath = 'files/' + f.filename
        f.save(filePath)
        f.close()
        encryptor = AESEncryptor(key)
        print(filePath)
        encryptor.encrypt_file(filePath)
        return jsonify(
            {
                "message": "success!"
            }
    )

    if request.method == 'GET':
        filePath = '/files/' + request.form['filename'] + '.enc'
        filePathFull = os.getcwd() + filePath
        encryptor = AESEncryptor(key)
        newFileDir = os.getcwd() + '/decrypt/' + 'temp'

        encryptor.decrypt_file(filePathFull)
        return send_file(newFileDir) 
        
    return jsonify(
        {
            "message": "invalid method."
        }
    )

@api.route('/rc4', methods=['POST', 'GET'])
def RC4Handler() -> json:
    username = request.form['username']
    password = request.form['password']
    key = request.form['key']

    cur = mysql.connection.cursor()
    queryString = "SELECT password FROM user WHERE username = '" + username + "'"
    cur.execute(queryString)
    rv = cur.fetchall()
    if password != rv[0][0]:
        return jsonify(
            {
                "message": "invalid username or password"
            }
        )

    if request.method == 'POST':
        f = request.files['file']
        filePath = 'files/' + f.filename
        f.save(filePath)
        f.close()
        pre_encrypt(filePath, key)
        print(filePath)
        os.remove(filePath)
        return jsonify(
            {
                "message": "success!"
            }
    )

    if request.method == 'GET':
        filePath = '/files/' + request.form['filename'] + '.enc'
        filePathFull = os.getcwd() + filePath
        pre_decrypt(filePathFull, key)
        newFileDir = os.getcwd() + '/decrypt/' + 'temp'
        
        return send_file(newFileDir) 
        
    return jsonify(
        {
            "message": "invalid method."
        }
    )

# @api.route('/create_user', methods=['POST'])
# def create_user():
#     try:
#         username = request.form.get('username')
#         email = request.form.get('email')
#         password = request.form.get('password')

#         # Create a new user in userss
#         cursor = mysql.connection.cursor()
#         cursor.execute("INSERT INTO userss (username, email, password) VALUES (%s, %s, %s) RETURNING user_id", (username, email, password))
#         new_user_id = cursor.fetchone()[0]
#         cursor.close()

#         return jsonify({"message": "User created successfully with user_id: " + str(new_user_id)})

#     except Exception as e:
#         return jsonify({"error": str(e)})

# @api.route('/upload', methods=['POST'])
# def upload_file():
#     user_id = request.form.get('user_id')
#     file = request.files['file']

#     if file:
#         try:
#             # Store the file
#             file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{user_id}_file.txt')
#             file.save(file_path)

#             iv = os.urandom(8) 

#             # Create a Cipher object for DES in CBC mode with the IV
#             cipher = Cipher(algorithms.TripleDES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
#             encryptor = cipher.encryptor()

#             file_data = open(file_path, 'rb').read()

#             # Apply PKCS7 padding to the file data
#             padder = PKCS7(64).padder()
#             padded_file_data = padder.update(file_data) + padder.finalize()

#             # Encrypt the padded file data
#             encrypted_file_data = encryptor.update(padded_file_data) + encryptor.finalize()

#             # Store the encrypted data in a text file
#             encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{user_id}_encrypted_file.txt')
#             with open(encrypted_file_path, 'wb') as encrypted_file:
#                 encrypted_file.write(encrypted_file_data)

#             cursor = database.cursor()
#             cursor.execute("UPDATE userss SET file_name = %s, file_data = %s, iv = %s WHERE user_id = %s",
#                            ('file', encrypted_file_data, iv, user_id))
#             database.commit()
#             cursor.close()

#             return jsonify({"message": "File uploaded and encrypted successfully."})
#         except Exception as e:
#             return jsonify({"error": str(e)})
#     return jsonify({"error": "No File file provided."})


# @api.route('/get_decrypted/<user_id>', methods=['GET'])
# def get_decrypted(user_id):
#     try:
#         # Retrieve the encrypted file data and IV from the database based on user_id
#         cursor = database.cursor()
#         cursor.execute("SELECT file_data, iv FROM userss WHERE user_id = %s", (user_id,))
#         result = cursor.fetchone()
#         cursor.close()

#         if result:
#             encrypted_file_data, iv = result
#             # Decrypt the file using DES in CBC mode
#             cipher = Cipher(algorithms.TripleDES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
#             decryptor = cipher.decryptor()
#             decrypted_file_data = decryptor.update(encrypted_file_data) + decryptor.finalize()

#             # Unpad the decrypted data using PKCS7
#             unpadder = PKCS7(64).unpadder()
#             unpadded_data = unpadder.update(decrypted_file_data) + unpadder.finalize()

#             # Create a response with the decrypted data
#             response = Response(unpadded_data)
#             return response

#         return jsonify({"error": "File not found for the given user."})

#     except Exception as e:
#         return jsonify({"error": str(e)})
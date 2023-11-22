from flask import Flask, json, jsonify, request, send_file, render_template, url_for, redirect
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_mysqldb import MySQL
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, ForeignKey, MetaData, String
from algorithm import *
from flask_bcrypt import Bcrypt
from sqlalchemy.sql import func
from form import *
from flask_uploads import configure_uploads, UploadSet, ALL
from init import *
import json

initRes = flaskInit()
api = initRes.get('api')
bcrypt = initRes.get('bcrypt')
login_manager = initRes.get('login_manager')
db = initRes.get('db')
metadata_obj = initRes.get('metadata_obj')
filesUploadSet = initRes.get('filesUploadSet') 


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
# user = db.Table(
#     "user",
#     Column('id', Integer, primary_key=True, autoincrement=True),
#     Column('username', String(20), unique=True),
#     Column('password', String(80), unique=True)
# )

files = db.Table(
    "files",
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('user_id', Integer, ForeignKey("user.id"), nullable=False),
    Column('filename', String(50), nullable=False)
)

privateData = db.Table(
    "private_data",
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('data_name', String(50), nullable=True),
    Column('user_id', Integer, ForeignKey("user.id"), nullable=False),
    Column('data', String(50), nullable=True)
)


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
    privateDataForm= PrivateDataForm()
    fileUploadForm= FileUploadForm()
    privateDataArr = None
    privateDataFilePath = os.getcwd() + '/private_data/' + current_user.get_id() + '.enc'
    filesArray = None
    fileDataPathRelative = '/files/' + current_user.get_id() + '/'
    fileDataPath = os.getcwd() + fileDataPathRelative
    tempFilePath = os.getcwd() + '/temp_download/temp'


    if os.path.exists(fileDataPath):
        dirList = getAllFiles(fileDataPathRelative)
        if len(dirList) > 0:
            filesArray = dirList.copy()
            
    if os.path.exists(privateDataFilePath):
        with open(privateDataFilePath, 'rb') as fo:
            dataEncrypted = fo.read()
            dataDecrypted = decrypt_data_cbc(dataEncrypted.decode(), SECRET_KEY.encode('utf-8'))
            dataArray = json.loads(dataDecrypted)
            privateDataArr = dataArray.copy()

    if request.method == 'POST' and filesArray != None and request.form.get('download') != None:
        for filePOSTName in filesArray:
            if request.form['download'] == filePOSTName:
                print(request.form['download'])
                filePathDir = fileDataPath + filePOSTName
                print('this is filepathdir')
                print(filePathDir)
                with open(filePathDir, "rb") as fo:
                    encryptFile = fo.read()
                    decryptFile = decrypt_data_cbc(encryptFile.decode(), SECRET_KEY.encode('utf-8'))
                    print(decryptFile)
                    with open(tempFilePath, "wb") as fr:
                        fr.write(decryptFile.encode('utf-8'))
                return send_file(tempFilePath)

    if privateDataForm.validate_on_submit():
        if privateData.select().where(privateData.c.user_id == current_user.get_id()) == None:
            privateData.insert().values(user_id = current_user.get_id())
        
        data = {
            f'{privateDataForm.data_name.data}' : f'{privateDataForm.data_isi.data}'
        }

        dataMerged = None
        if privateDataArr != None:
            dataMerged = data | privateDataArr
        else:
            dataMerged = data

        privateDataArr = dataMerged
        dataJson = json.dumps(dataMerged)
        encryptedData = encrypt_data_cbc(dataJson.encode('utf-8'), IV.encode('utf-8'), SECRET_KEY.encode('utf-8'))
        with open(privateDataFilePath, 'wb') as fo:
            fo.write(encryptedData.encode('utf-8'))
        
        return render_template('dashboard.html', privateDataForm=privateDataForm, uploadFileForm=fileUploadForm, privateDataArr=privateDataArr, filesArray=filesArray)
    
    if fileUploadForm.validate_on_submit():
        tempFilePath = os.getcwd() + '/temp_download/temp'
        newFilePathDir = os.getcwd() + '/files/' + current_user.get_id() + '/'
        newFilePath = newFilePathDir + fileUploadForm.file.data.filename

        if not os.path.exists(newFilePathDir):
            os.makedirs(newFilePathDir)

        filesUploadSet.save(fileUploadForm.file.data, name="temp")
        with open(tempFilePath, 'rb') as fo:
            fileData = fo.read()
            encrypted_file = encrypt_data_cbc(fileData, IV.encode('utf-8'), SECRET_KEY.encode('utf-8'))
            with open(newFilePath, 'wb') as fr:
                fr.write(encrypted_file.encode('utf-8'))
        os.remove(tempFilePath)
        if filesArray is not None:
            filesArray.append(fileUploadForm.file.data.filename)
        else:
            filesArray = [fileUploadForm.file.data.filename]
            

        return render_template('dashboard.html', privateDataForm=privateDataForm, uploadFileForm=fileUploadForm, privateDataArr=privateDataArr, filesArray=filesArray)
    

    return render_template('dashboard.html', privateDataForm=privateDataForm, uploadFileForm=fileUploadForm, privateDataArr=privateDataArr, filesArray=filesArray)

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

def getAllFiles(relativeFilePath: str):
    dir_path = os.getcwd()
    dirs = []
    for dirName, subDirList, fileList in os.walk(dir_path + '/' + relativeFilePath):
        dirs.append(fileList)
    return dirs[0]
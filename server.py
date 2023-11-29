from flask import json, jsonify, request, send_file, render_template, url_for, redirect
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_mysqldb import MySQL
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, ForeignKey, MetaData, String
from algorithm import *
from form import *
from init import *
import json
from Crypto import Random

initRes = flaskInit()
api = initRes.get('api')
bcrypt = initRes.get('bcrypt')
login_manager = initRes.get('login_manager')
db = initRes.get('db')
metadata_obj = initRes.get('metadata_obj')
filesUploadSet = initRes.get('filesUploadSet') 
PRIVATE_DATA_FILE_PATH = initRes.get('PRIVATE_DATA_FILE_PATH')
TEMP_FILE_FILE_PATH = initRes.get('TEMP_FILE_FILE_PATH')
FILE_DATA_FILE_PATH = initRes.get('FILE_DATA_FILE_PATH')
FILE_DATA_FOLDER_NAME = initRes.get('FILE_DATA_FOLDER_NAME')
TEMP_FILE_FOLDER_NAME = initRes.get('TEMP_FILE_FOLDER_NAME')
SECRET_KEY = api.secret_key.encode('utf-8')
IV = Random.get_random_bytes(8)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(100))
    public_key = db.Column(db.String(513), nullable=False)
    private_key = db.Column(db.String(513), nullable=False)
    symmetric_key = db.Column(db.String(513), nullable=False)
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


@api.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    privateDataForm= PrivateDataForm()
    fileUploadForm= FileUploadForm()
    privateDataArr = None
    filesArray = None

    privateDataFilePath = PRIVATE_DATA_FILE_PATH + '/' + current_user.get_id() + '.enc'
    fileDataPath = FILE_DATA_FILE_PATH + '/' + current_user.get_id() + '/'
    # fileDataPathRelative = '/files/' + current_user.get_id() + '/'
    tempFilePath = os.getcwd() + '/temp_download/temp'

    if os.path.exists(fileDataPath):
        dirList = getAllFiles(fileDataPath)
        if len(dirList) > 0:
            filesArray = dirList.copy()
            
    if os.path.exists(privateDataFilePath):
        with open(privateDataFilePath, 'rb') as fo:
            dataEncrypted = fo.read()
            dataDecrypted = decrypt_data_cbc(dataEncrypted.decode(), SECRET_KEY)
            dataArray = json.loads(dataDecrypted)
            privateDataArr = dataArray.copy()
            
    return render_template('dashboard.html', privateDataForm=privateDataForm, uploadFileForm=fileUploadForm, privateDataArr=privateDataArr, filesArray=filesArray)

@api.route('/postPrivateData', methods=['POST'])
def postPrivateData():
    privateDataForm= PrivateDataForm()

    privateDataArr = None
    privateDataFilePathUser = PRIVATE_DATA_FILE_PATH + '/' +current_user.get_id() + '.enc'

    if privateData.select().where(privateData.c.user_id == current_user.get_id()) == None:
        privateData.insert().values(user_id = current_user.get_id())

    if os.path.exists(privateDataFilePathUser):
        with open(privateDataFilePathUser, 'rb') as fo:
            dataEncrypted = fo.read()
            dataDecrypted = decrypt_data_cbc(dataEncrypted.decode(), SECRET_KEY)
            dataArray = json.loads(dataDecrypted)
            privateDataArr = dataArray.copy()
    
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
    encryptedData = encrypt_data_cbc(dataJson.encode('utf-8'), IV, SECRET_KEY)
    with open(privateDataFilePathUser, 'wb') as fo:
        fo.write(encryptedData.encode('utf-8'))
    
    return redirect('/dashboard')

@api.route('/postFiles', methods=['POST'])
def postFiles():
    fileUploadForm= FileUploadForm()
    # fileDataPathRelative = '/files/' + current_user.get_id() + '/'
    fileDataPath = FILE_DATA_FILE_PATH + '/' + current_user.get_id() + '/'
    tempFilePath = TEMP_FILE_FILE_PATH + '/temp'

    filename = fileUploadForm.file.data
    print('THIS IS FILENAME ')
    print(filename)
    if filename != '':
        file_ext = os.path.splitext(filename)[1]
        print(file_ext)

    if not os.path.exists(fileDataPath):
        os.mkdir(fileDataPath)
    
    # print(fileUploadForm.file.data)
    tempFilePath = TEMP_FILE_FILE_PATH + '/temp' + fileUploadForm.data
    newFilePath = fileDataPath + fileUploadForm.file.data.filename

    filesUploadSet.save(fileUploadForm.file.data, name='temp' + '.')
    with open(tempFilePath, 'rb') as fo:
        fileData = fo.read()
        encrypted_file = encrypt_data_cbc(fileData, IV, SECRET_KEY)
        with open(newFilePath, 'wb') as fr:
            fr.write(encrypted_file.encode('utf-8'))
    os.remove(tempFilePath)        

    return redirect('/dashboard')

@api.route('/downloadFile', methods=['POST'])
def downloadFile():
    filesArray = None
    fileDataPath = FILE_DATA_FILE_PATH + '/' + current_user.get_id() + '/'

    if os.path.exists(fileDataPath):
            dirList = getAllFiles(fileDataPath)
            if len(dirList) > 0:
                filesArray = dirList.copy()
    for filePOSTName in filesArray:
        if request.form['download'] == filePOSTName:
            filePathDir = fileDataPath + filePOSTName
            with open(filePathDir, "rb") as fo:
                encryptFile = fo.read()
                decryptFile = decrypt_data_cbc(encryptFile.decode(), SECRET_KEY)
                print(decryptFile)
                with open(fileDataPath, "wb") as fr:
                    fr.write(decryptFile.encode('utf-8'))
            return send_file(fileDataPath)

@api.route('/test', methods=['GET'])
def test() -> json:
    return jsonify({
        "message": "Hello World"
    })

def getAllFiles(fullFilePath: str):
    # dir_path = os.getcwd()
    dirs = []
    for dirName, subDirList, fileList in os.walk(fullFilePath):
        dirs.append(fileList)
    print(fullFilePath)
    print(dirs)
    return dirs[0]
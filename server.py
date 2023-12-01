from flask import json, jsonify, request, send_file, render_template, url_for, redirect
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_mysqldb import MySQL
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, ForeignKey, MetaData, String, select, Table
from algorithm import *
from form import *
from init import *
import json
from Crypto import Random
from helper import *

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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(100))
    public_key = db.Column(db.String(3000), nullable=False)
    private_key = db.Column(db.String(3000), nullable=False)
    symmetric_key = db.Column(db.String(3000), nullable=False)

class files(db.Model):
    id = db.Column(Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('files', lazy=True))
    filename = db.Column(String(50), nullable=False)
    file_extension = db.Column(String(50), nullable=True)
    user = db.relationship('User', backref='uploaded_files')

class privateData(db.Model):
    id = db.Column(Integer, primary_key=True, autoincrement=True)
    data_name = db.Column('data_name', String(50), nullable=True)
    user_id = db.Column(Integer, ForeignKey("user.id"), nullable=False)
    data = db.Column(String(50), nullable=True)

class FileRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='pending')
    file = db.relationship('files', backref=db.backref('requests', lazy=True))
    requester = db.relationship('User', foreign_keys=[requester_id])


@api.route('/files', methods=['GET'])
@login_required
def list_files():
    Files = files.query.all()
    file_data = []
    for file in Files:
        request = FileRequest.query.filter_by(file_id=file.id, requester_id=current_user.id).first()
        status = request.status if request else 'not requested'
        file_data.append({'id': file.id, 'filename': file.filename, 'username': file.user.username, 'status': status})
    return render_template('request_file.html', files=file_data)

@api.route('/request_file', methods=['POST'])
@login_required
def request_file():
    file_id = request.form.get('file_id')
    file = files.query.get(file_id)
    new_request = FileRequest(
        file_id=file_id,
        requester_id=current_user.id,
        owner_id=file.user_id,
        status='waiting confirmation'
    )
    db.session.add(new_request)
    db.session.commit()
    return redirect(url_for('list_files'))

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
        keys = createKeys()
        new_user = User(username=form.username.data, password=hashed_password, email=form.email.data, public_key=keys.get('publicKey'), private_key=keys.get('privateKey'), symmetric_key=keys.get('symmetricKeyEncrypted'))
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@api.route('/update_request_status', methods=['POST'])
@login_required
def update_request_status():
    request_id = request.form.get('request_id')
    new_status = request.form.get('status')  # accepted or declined

    file_request = FileRequest.query.get(request_id)
    if file_request and file_request.owner_id == current_user.id:
        file_request.status = new_status
        db.session.commit()
        if(new_status == 'accepted'):
            query = select(User).where(file_request.requester_id == User.id)
            res = db.session.execute(query).first()
            for row in res:
                requesterEmail = row.email
                requesterPublicKey = row.public_key
            sendEmail(requesterEmail, generateSymmetricKey(), requesterPublicKey)
        return redirect(url_for('manage_requests'))
    return 'Invalid Request', 400

@api.route('/manage_requests', methods=['GET'])
@login_required
def manage_requests():
    # Fetch requests where the current user is the owner of the requested file
    incoming_requests = FileRequest.query \
        .join(files, FileRequest.file_id == files.id) \
        .filter(files.user_id == current_user.id).all()

    return render_template('manage_request.html', requests=incoming_requests)
@api.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    privateDataForm= PrivateDataForm()
    fileUploadForm= FileUploadForm()
    privateDataArr = None
    filesArray = list()

    privateDataFilePath = PRIVATE_DATA_FILE_PATH + '/' + current_user.get_id() + '.enc'

    # Query for searching all uploaded files
    query = select(files).where(files.user_id == current_user.get_id())
    res = db.session.execute(query).all()
    for listRes in res:
        for row in listRes:
            filesArray.append(f'{row.filename}.{row.file_extension}')
            
    # Search for all private data
    if os.path.exists(privateDataFilePath):
        with open(privateDataFilePath, 'rb') as fo:
            dataEncrypted = fo.read()
            dataDecrypted = decrypt_data_cbc(dataEncrypted.decode(), getSymmetricKey(current_user.get_id(), db))
            dataArray = json.loads(dataDecrypted)
            privateDataArr = dataArray.copy()
            
    return render_template('dashboard.html', privateDataForm=privateDataForm, uploadFileForm=fileUploadForm, privateDataArr=privateDataArr, filesArray=filesArray)

@api.route('/postPrivateData', methods=['POST'])
def postPrivateData():
    privateDataForm= PrivateDataForm()

    privateDataArr = None
    privateDataFilePathUser = PRIVATE_DATA_FILE_PATH + '/' +current_user.get_id() + '.enc'

    if os.path.exists(privateDataFilePathUser):
        with open(privateDataFilePathUser, 'rb') as fo:
            dataEncrypted = fo.read()
            dataDecrypted = decrypt_data_cbc(dataEncrypted.decode(), getSymmetricKey(current_user.get_id(), db))
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
    encryptedData = encrypt_data_cbc(dataJson.encode(), generateIV(), getSymmetricKey(current_user.get_id(), db))
    with open(privateDataFilePathUser, 'wb') as fo:
        fo.write(encryptedData.encode('utf-8'))
    
    return redirect('/dashboard')

@api.route('/postFiles', methods=['POST'])
def postFiles():
    fileUploadForm = FileUploadForm()
    fileDataPath = FILE_DATA_FILE_PATH + '/'
    tempFilePath = TEMP_FILE_FILE_PATH + '/temp'

    if not os.path.exists(fileDataPath):
        os.mkdir(fileDataPath)
    
    fileName = getFileName(fileUploadForm.file.data.filename)
    extension = getFileExtension(fileUploadForm.file.data.filename)
    new_file = files(user_id = current_user.get_id(), filename = fileName, file_extension = extension)
    db.session.add(new_file)
    db.session.commit()
    query = select(Column('id')).where(files.user_id == current_user.get_id()).where(files.filename == fileName)
    res = db.session.execute(query)
    fileId = None
    for resIndividu in res.scalars():
        fileId = resIndividu

    newFilePath = fileDataPath + "{}".format(fileId)

    filesUploadSet.save(fileUploadForm.file.data, name='temp')  
    with open(tempFilePath, 'rb') as fo:
        fileData = fo.read()
        encrypted_file = encrypt_data_cbc_file(fileData, generateIV(), getSymmetricKey(current_user.get_id(), db))
        with open(newFilePath, 'wb') as fr:
            fr.write(encrypted_file)
    os.remove(tempFilePath)

    return redirect('/dashboard')

@api.route('/downloadFile', methods=['POST'])
def downloadFile():
    filesMetadata = dict()
    fileName = getFileName(request.form['download'])
    fileDataFolderPath = FILE_DATA_FILE_PATH + '/'

    query = select(files).where(files.user_id == current_user.get_id()).where(files.filename == fileName)
    res = db.session.execute(query).first()
    for row in res:
        filesMetadata['filename'] = row.filename 
        filesMetadata['file_extension'] = row.file_extension 
        filesMetadata['id'] = row.id 

        fileDataPath = FILE_DATA_FILE_PATH + '/' + f'{filesMetadata["filename"]}.{filesMetadata["file_extension"]}'
        filePathDir = fileDataFolderPath + f'{filesMetadata["id"]}'
        with open(filePathDir, "rb") as fo:
            encryptFile = fo.read()
            decryptFile = decrypt_data_cbc_file(encryptFile, getSymmetricKey(current_user.get_id(), db))
            with open(fileDataPath, "wb") as fr:
                fr.write(decryptFile)
                return send_file(fileDataPath, as_attachment=True)

    return redirect('/dashboard')
    
@api.route('/getPrivateKey', methods=['GET'])
def getPrivateKey():
    privateKey = getPrivateKey(current_user.get_id(), db)
    return render_template('private_key.html', privateKey= privateKey)


@api.route('/test', methods=['GET'])
def test() -> json:
    return jsonify({
        "message": "Hello World"
    })

def getSymmetricKey(userId, db):
    userDict = dict()
    query = select(User).where(User.id == userId)
    res = db.session.execute(query).first()

    for row in res:
        userDict['private_key'] = row.private_key
        userDict['symmetric_key'] = row.symmetric_key

    return decrypt_bytes(userDict['symmetric_key'], userDict['private_key'])

def getPrivateKey(userId, db):
    query = select(User).where(User.id == userId)
    res = db.session.execute(query).first()

    for row in res:
        privateKey = row.private_key

    return privateKey
from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData
from algorithm import *
from flask_bcrypt import Bcrypt
from form import *
from flask_uploads import configure_uploads, UploadSet, ALL
from dotenv import load_dotenv

def flaskInit():
    load_dotenv()
    api = Flask(__name__)
            
    api.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
    api.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
    api.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
    api.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
    api.config['MYSQL_PORT'] = os.getenv('MYSQL_PORT')
    # mysql = MySQL(api)
    bcrypt = Bcrypt(api)

    api.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')
    api.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    api.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('UPLOAD_FOLDER')
    db = SQLAlchemy(api)
    metadata_obj = MetaData()
    login_manager = LoginManager()
    login_manager.init_app(api)
    login_manager.login_view = 'login'

    # api.config['UPLOADED_FILES_DEST'] = os.getcwd() + '/temp_download'
    api.config['UPLOADED_FILES_DEST'] = os.getenv('UPLOADED_FILES_DEST')
    filesUploadSet = UploadSet('files')
    configure_uploads(api, filesUploadSet)
    return {
        'api': api,
        'bcrypt': bcrypt,
        'db': db,
        'metadata_obj': metadata_obj,
        'login_manager': login_manager,
        'filesUploadSet': filesUploadSet,
    }

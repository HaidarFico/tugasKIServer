from flask import Flask, json, jsonify, request, send_file
from flask_mysqldb import MySQL
from algorithm import *


api = Flask(__name__)
        
api.config['MYSQL_HOST'] = '127.0.0.1'
api.config['MYSQL_USER'] = 'root'
api.config['MYSQL_PASSWORD'] = 'change-me'
api.config['MYSQL_DB'] = 'KI'
api.config['MYSQL_PORT'] = 3306
api.config['UPLOAD_FOLDER'] = 'files'
mysql = MySQL(api)

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

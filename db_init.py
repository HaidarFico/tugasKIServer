from server import db, api

with api.app_context():
    db.create_all()
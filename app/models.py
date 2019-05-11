from app import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(500), unique=True, nullable=False)
    salt = db.Column(db.String(500), unique=True, nullable=False)


class Passwords(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Account = db.Column(db.String(80), unique=True, nullable=False)
    Password = db.Column(db.String(500), unique=True, nullable=False)
    IV = db.Column(db.String(500), unique=True, nullable=False)
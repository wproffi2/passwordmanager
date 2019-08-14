from app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(500), unique=True, nullable=False)
    salt = db.Column(db.String(500), unique=True, nullable=False)


class Passwords(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Account = db.Column(db.String(80), unique=True, nullable=False)
    Password = db.Column(db.String(500), unique=True, nullable=False)
    IV = db.Column(db.String(500), unique=True, nullable=False)
    Count = db.Column(db.Integer, nullable=True)
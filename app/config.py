import os

from app import db_uri


JWT_SECRET_KEY = str(os.urandom(16))
JWT_TOKEN_LOCATION = ['cookies']
JWT_COOKIE_CSRF_PROTECT = False
SQLALCHEMY_DATABASE_URI = db_uri#'sqlite:///{}'.format(db_name)
SQLALCHEMY_TRACK_MODIFICATIONS = False
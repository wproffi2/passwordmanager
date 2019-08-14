from flask_sqlalchemy import SQLAlchemy
from pyfladesk import init_gui
from flask import Flask
import sys, os



def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    
    return os.path.join(base_path, relative_path)

db_name = 'app.db'

if getattr(sys, 'frozen', False):
    
    cur_dir = resource_path(db_name)
    template_folder = resource_path('templates')
    static_folder = resource_path('static')
    application = Flask(__name__, template_folder=template_folder, static_folder=static_folder)
        
else:
    cur_dir = os.path.join(os.path.dirname(__file__), db_name)
    application = Flask(__name__)

db_uri = 'sqlite:///{}'.format(cur_dir)

application.config.from_pyfile('config.py')


db = SQLAlchemy(application)
from views import *

if __name__ == '__main__':
    db.create_all()
    init_gui(application)
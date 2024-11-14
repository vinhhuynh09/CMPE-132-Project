from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os

# Initialize the extensions
db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    # Initialize the Flask app
    myapp_obj = Flask(__name__)

    # Set the configuration for the app
    basedir = os.path.abspath(os.path.dirname(__file__))
    myapp_obj.config.from_mapping(
        SECRET_KEY='you-will-never-guess',
        SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(basedir, 'app.db'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False
    )

    # Initialize extensions
    db.init_app(myapp_obj)
    login_manager.init_app(myapp_obj)

    # Register the blueprints or routes (this should be imported last to avoid circular imports)
    with myapp_obj.app_context():
        from . import routes  # Make sure routes are registered
        from .models import Users  # Ensure the models are loaded

        db.create_all()  # Create all database tables (if they don't exist)

    return myapp_obj


"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os
from flask_login import LoginManager

myapp_obj = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(myapp_obj)

basedir = os.path.abspath(os.path.dirname(__file__))

myapp_obj.config.from_mapping(
    SECRET_KEY = 'you-will-never-guess',
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS = False
)

db = SQLAlchemy(myapp_obj)

login_manager = LoginManager(myapp_obj)
login_manager.login_view = '/home'

with myapp_obj.app_context():
    from app.models import Users, Notes, Folders
    db.create_all()

from app import routes

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))
"""
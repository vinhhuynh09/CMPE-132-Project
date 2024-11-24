from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

# Initialize the SQLAlchemy instance
db = SQLAlchemy()

# Define the User model which represents a user in the database
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default="Member")

    def __repr__(self):
        return f"<User {self.username}>"

# load a user for flask-Login
def load_user(user_id):
    return User.query.get(int(user_id))
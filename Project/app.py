from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from wtforms import Form, StringField, PasswordField, SelectField, BooleanField, validators
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, EqualTo, Email

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sjsul.db'
app.config['SECRET_KEY'] = 'secure_key_here'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default="Member")

    def __repr__(self):
        return f"<User {self.username}>"

# WTForms for Create Account and Login
class CreateAccountForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('Admin', 'Admin'), ('Librarian', 'Librarian'), ('Member', 'Member')])
    submit = StringField('Create Account')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')

# Routes
@app.route('/')
def login():
    form = LoginForm()
    return render_template('login.html', form=form)

@app.route('/createaccount', methods=['GET', 'POST'])
def createaccount():
    form = CreateAccountForm()
    if request.method == 'POST' and form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            name=form.name.data,
            email=form.email.data,
            username=form.username.data,
            password=hashed_password,
            role=form.role.data,
        )
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('createaccount.html', form=form)

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('home.html')

if __name__ == '__main__':
    with app.app_context():

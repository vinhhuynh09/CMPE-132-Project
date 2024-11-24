from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, SelectField, BooleanField, SubmitField
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, EqualTo, Email, ValidationError

# Initialize the Flask application
app = Flask(__name__)

# Configuration for the SQLite database and secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sjsul.db'
app.config['SECRET_KEY'] = 'secure_key_here'

# Initialize database and password hashing utility
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

    # String representation for debugging purposes
    def __repr__(self):
        return f"<User {self.username}>"

# WTForms for Create Account and Login
class CreateAccountForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(message="Name is required.")])
    email = StringField('Email', validators=[
        DataRequired(message="Email is required."),
        Email(message="Enter a valid email address.")
    ])
    username = StringField('Username', validators=[DataRequired(message="Username is required.")])
    password = PasswordField('Password', validators=[DataRequired(message="Password is required.")])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(message="Confirm Password is required.")])
    role = SelectField('Role', choices=[('Admin', 'Admin'), ('Librarian', 'Librarian'), ('Member', 'Member')])
    submit = SubmitField('Create Account')

    # custom validation for password confirmation
    def validate_confirm(self, confirm):
        if confirm.data != self.password.data:
            raise ValidationError("Passwords do not match.")

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Routes
@app.route('/')
def login():
    form = LoginForm()
    return render_template('login.html', form=form)

@app.route('/login', methods=['POST'])
def handle_login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/createaccount', methods=['GET', 'POST'])
def createaccount():
    form = CreateAccountForm()
    if form.validate_on_submit():
        # Hash the password
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        # Create a new user object
        user = User(
            name=form.name.data,
            email=form.email.data,
            username=form.username.data,
            password=hashed_password,
            role=form.role.data
        )

        # Add the user to the database and commit changes
        db.session.add(user)
        db.session.commit()

        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('createaccount.html', form=form)

@app.route('/home')
def home():
    # Check if user is logged in
    if 'user_id' not in session:
        flash('You need to log in to access this page.', 'warning')
        return redirect(url_for('login'))
    return render_template('home.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
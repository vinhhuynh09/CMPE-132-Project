# routes.py
from flask import render_template, redirect, flash, request
from app import myapp_obj, db
from .models import Users
from flask_login import login_user, current_user, logout_user, login_required
from sqlalchemy import asc, desc
from .forms import LoginForm, CreateAccountForm

@myapp_obj.route("/", methods=['GET', 'POST'])
@myapp_obj.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        print("Form is valid and submitted")

        user = Users.query.filter_by(username=form.username.data).first()

        if user and user.check_password(form.password.data):
            # Valid login
            login_user(user, remember=form.remember_me.data)
            print('True')
            return redirect('/home')  

        else:
            # Invalid login
            flash('Invalid username or password. Please try again.', 'error')

    return render_template('login.html', form=form)

@myapp_obj.route("/createaccount", methods=['GET', 'POST'])
def createaccount():
    form = CreateAccountForm()

    # If form is submitted and valid
    if form.validate_on_submit():
        # If form is valid, create the user
        print('Form is valid')
        print(f'This is the username of the user: {form.username.data}')
        print(f'This is the password of the user: {form.password.data}')

        u = Users(username=form.username.data, password=form.password.data, email=form.email.data)
        u.set_password(form.password.data)
        db.session.add(u)
        db.session.commit()

        flash('Account created successfully!', 'success')
        return redirect('/home')

    else:
        # Handle errors for email or password mismatch
        if 'email' in form.errors:
            flash('Invalid email format. Please enter a valid email address.', 'error')

        if 'confirm' in form.errors:
            flash('Passwords do not match. Please make sure the passwords match.', 'error')

        # Render the create account page with the form (so the user sees the errors)
        return render_template('createaccount.html', form=form)

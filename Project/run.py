from flask import Flask, render_template, redirect, flash, request
from forms import LoginForm, CreateAccountForm
#from app import db
#from models import Users

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Add a secret key for CSRF protection

@app.route("/")
@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        print('Login requested for user {}, remember_me={}'.format(form.username.data, form.remember_me.data))
        return redirect('/')
    return render_template('login.html', form=form)

@app.route("/createaccount")
def createaccount():
    form = CreateAccountForm()
    if form.validate_on_submit():
        u = Users(username=form.username.data, password=form.password.data, email=form.email.data)
        u.set_password(form.password.data)
        db.session.add(u)
        db.session.commit()
        return redirect('/home')
    return render_template('createaccount.html', form=form)

if __name__ == "__main__":
    app.run(debug=True)

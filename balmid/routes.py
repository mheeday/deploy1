from flask import render_template, url_for, flash, redirect, request
from balmid import app, db, bcrypt
from balmid.forms import RegistrationForm, LoginForm
from balmid.models import User, Portfolio
from flask_login import login_user, current_user, logout_user, login_required


@app.route("/")
@app.route("/index")
@app.route("/home")
def index():
    return render_template("index.html", title='Home')

@app.route('/login', methods=["POST", "GET"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            flash(f"Welcome, {current_user.first_name}", 'success')
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            else:
                return redirect(url_for('index'))
        else:    
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template("login.html", title='Log In', form=form)

@app.route('/register', methods=["POST", "GET"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(first_name=form.first_name.data, last_name=form.last_name.data, 
                    email=form.email.data, phone=form.phone.data,
                    password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!, You can now login.', 'success')
        return redirect(url_for('login'))
    return render_template("register.html", title="Register", form=form)

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/products')
def products():
    return render_template("products.html", title="Products")

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/personalinvestment')
def personalinvestment():
    return render_template("personalinvestment.html")

@app.route('/dashboard')
@login_required
def dashboard():
    pass
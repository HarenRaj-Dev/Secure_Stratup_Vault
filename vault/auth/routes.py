from flask import render_template, url_for, flash, redirect, request
from flask_login import login_user, current_user, logout_user, login_required
from vault import db
from vault.models import User
from vault.auth import auth_bp
from vault.auth.forms import RegistrationForm, LoginForm
from vault.crypto_utils import generate_user_keys
from werkzeug.security import generate_password_hash, check_password_hash

@auth_bp.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=True)
            return redirect(url_for('main.dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
            
    return render_template('auth/login.html', form=form)

@auth_bp.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        from vault.crypto_utils import generate_user_keys
        priv_key, pub_key = generate_user_keys()
        
        hashed_password = generate_password_hash(password)
        new_user = User(
            email=email, 
            password=hashed_password,
            rsa_private_key=priv_key,
            rsa_public_key=pub_key
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please login.', 'success')
        return redirect(url_for('auth.login'))
        
    return render_template('auth/login.html', form=RegistrationForm())

@auth_bp.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_login import login_manager
from dotenv import load_dotenv
import psycopg2

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# Database URL
DATABASE_URL = os.getenv("DATABASE_URL")

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Database connection function
def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

# User class to work with Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, first_name, last_name):
        self.id = id
        self.username = username
        self.email = email
        self.first_name = first_name
        self.last_name = last_name

    @staticmethod
    def get(user_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, first_name, last_name FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            # Unpack the data correctly (5 fields expected)
            return User(*user_data)
        return None


# User loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Define forms
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=100)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=100)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class ProfileEditForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])

# Routes

@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, email, password, first_name, last_name) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                       (form.username.data, form.email.data, form.password.data, form.first_name.data, form.last_name.data))
        user_id = cursor.fetchone()[0]
        conn.commit()
        conn.close()

        # Pass only the necessary fields (5 fields)
        user = User(user_id, form.username.data, form.email.data, form.first_name.data, form.last_name.data)
        login_user(user)

        flash('Registration successful!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, first_name, last_name FROM users WHERE username = %s AND password = %s", 
                       (form.username.data, form.password.data))
        user_data = cursor.fetchone()
        conn.close()

        if user_data:
            user = User(*user_data)  # Unpack only 5 fields from user_data
            login_user(user)
            return redirect(url_for('dashboard'))

        flash('Invalid username or password.', 'danger')

    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def profile_edit():
    form = ProfileEditForm(obj=current_user)
    if form.validate_on_submit():
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users 
            SET first_name = %s, last_name = %s, email = %s
            WHERE id = %s
        """, (form.first_name.data, form.last_name.data, form.email.data, current_user.id))
        conn.commit()
        conn.close()

        flash('Profile updated!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('profile_edit.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)

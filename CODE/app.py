

#================================================================================================================================================================

import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
from sqlalchemy.exc import IntegrityError
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SelectField, IntegerField, FloatField, BooleanField
from wtforms.validators import DataRequired, Email, Length, NumberRange, Regexp
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
import logging
from logging.handlers import RotatingFileHandler
import bleach
from flask_limiter.errors import RateLimitExceeded
import re
import glob
from operator import itemgetter


#================================================================================================================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'your_secret_key'  # Use environment variable for production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Hamadabank.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY') or 'your_jwt_secret_key'  # Use environment variable for production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)  # Token expires after 30 minutes

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)


#================================================================================================================================================================



# Set up logging
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/hamadabank.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Hamada Bank startup')


#================================================================================================================================================================

def recreate_database():
    # Drop all tables
    db.drop_all()
    
    # Create all tables
    db.create_all()
    
    # Create admin user
    admin_password = generate_password_hash('admin123')  # You should change this password
    admin = User(username='admin', password=admin_password, first_name='Admin',
                 last_name='User', phone='1234567890', city='Admin City',
                 email='admin@example.com', account_type='admin', age=30, is_admin=True)
    db.session.add(admin)
    db.session.commit()
    print("Database recreated and admin user added.")



# Models
#================================================================================================================================================================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    city = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    account_type = db.Column(db.String(10), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    loan_amount = db.Column(db.Float, default=0.0)
    age = db.Column(db.Integer, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime)


#================================================================================================================================================================

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transaction_type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    balance = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    hash = db.Column(db.String(64), nullable=False)  # For integrity checking



#================================================================================================================================================================

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=15)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=15)])
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=15)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=15)])
    phone = StringField('Phone', validators=[DataRequired(), Regexp('^[0-9]{10,15}$', message='Phone number must be between 10 and 15 digits')])
    city = StringField('City', validators=[DataRequired(), Length(max=15)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    account_type = SelectField('Account Type', choices=[('savings', 'Savings'), ('current', 'Current'), ('islamic', 'Islamic')])
    age = IntegerField('Age', validators=[DataRequired(), NumberRange(min=18, max=120)])

#================================================================================================================================================================

class AdminCreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=15)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=15)])
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=15)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=15)])
    phone = StringField('Phone', validators=[DataRequired(), Regexp('^[0-9]{10,15}$', message='Phone number must be between 10 and 15 digits')])
    city = StringField('City', validators=[DataRequired(), Length(max=15)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    account_type = SelectField('Account Type', choices=[('savings', 'Savings'), ('current', 'Current'), ('islamic', 'Islamic')])
    age = IntegerField('Age', validators=[DataRequired(), NumberRange(min=18, max=120)])
    is_admin = BooleanField('Is Admin')





#================================================================================================================================================================


def generate_token(user_id):
    return jwt.encode({'user_id': user_id, 'exp': datetime.utcnow() + timedelta(minutes=30)},
                      app.config['JWT_SECRET_KEY'], algorithm='HS256')


#================================================================================================================================================================


def verify_token(token):
    try:
        data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return data['user_id']
    except:
        return None


#================================================================================================================================================================


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('token')
        if not token:
            flash('You need to log in to access this page.', 'error')
            return redirect(url_for('login'))
        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
        except:
            flash('Invalid session. Please log in again.', 'error')
            return redirect(url_for('login'))
        return f(current_user, *args, **kwargs)
    return decorated


#================================================================================================================================================================


@app.errorhandler(RateLimitExceeded)
def handle_rate_limit_exceeded(e):
    return render_template('rate_limit_exceeded.html'), 429

#================================================================================================================================================================

class DepositForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01, max=1000000)])



#================================================================================================================================================================

class WithdrawForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01, max=1000000)])


#================================================================================================================================================================

class LoanForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=100, max=1000000)])
    years = IntegerField('Years', validators=[DataRequired(), NumberRange(min=1, max=30)])
    loan_type = SelectField('Loan Type', choices=[('education', 'Education'), ('car', 'Car'), ('home', 'Home'), ('personal', 'Personal')])



#================================================================================================================================================================

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('token')
        if not token:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('login'))
        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
            if user:
                print(f"Admin access granted for user: {user.username}")
            if not user or not user.is_admin:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('dashboard'))
        except Exception as e:
            print(f"Admin access denied: {e}")
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


#================================================================================================================================================================

@app.before_request
def log_request_info():
    app.logger.info(f"Request Info: IP={request.remote_addr}, UserAgent={request.user_agent}, Method={request.method}, Path={request.path}")



#================================================================================================================================================================


@app.route('/')
def home():
    return render_template('home.html')


#================================================================================================================================================================

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=15)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=15)])


#================================================================================================================================================================

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limiting for brute force prevention
def login():
    try:
        form = LoginForm()
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            user = User.query.filter_by(username=username).first()
            
            if user and user.account_locked_until and user.account_locked_until > datetime.utcnow():
                flash('Account is locked. Please try again later.', 'error')
                return render_template('login.html', form=form)
            
            if user and check_password_hash(user.password, password):
                user.failed_login_attempts = 0
                db.session.commit()
                token = generate_token(user.id)
                session['token'] = token
                flash('Logged in successfully.', 'success')
                app.logger.info(f'User {username} logged in successfully')
                if user.is_admin:
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('dashboard'))
            else:
                if user:
                    user.failed_login_attempts += 1
                    if user.failed_login_attempts >= 5:
                        user.account_locked_until = datetime.utcnow() + timedelta(minutes=15)
                    db.session.commit()
                flash('Invalid username or password.', 'error')
                app.logger.warning(f'Failed login attempt for username: {username}')
        return render_template('login.html', form=form)
    except RateLimitExceeded:
        app.logger.warning(f'Rate limit exceeded for login from IP: {request.remote_addr}')
        return render_template('rate_limit_exceeded.html'), 429


#================================================================================================================================================================

@app.route('/logout')
def logout():
    session.pop('token', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))


#================================================================================================================================================================

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per hour")  # Rate limiting for registration
def register():
    try:
        form = RegistrationForm()
        if form.validate_on_submit():
            existing_user = User.query.filter_by(email=form.email.data).first()
            if existing_user:
                flash('Email address already in use. Please use a different email.', 'error')
                return redirect(url_for('register'))

            try:
                hashed_password = generate_password_hash(form.password.data)
                new_user = User(
                    username=form.username.data,
                    password=hashed_password,
                    first_name=form.first_name.data,
                    last_name=form.last_name.data,
                    phone=form.phone.data,
                    city=form.city.data,
                    email=form.email.data,
                    account_type=form.account_type.data,
                    age=form.age.data
                )
                db.session.add(new_user)
                db.session.commit()
                flash('Account created successfully. Please log in.', 'success')
                app.logger.info(f'New user registered: {form.username.data}')
                return redirect(url_for('login'))
            except IntegrityError:
                db.session.rollback()
                flash('An error occurred. Please try again.', 'error')
                return redirect(url_for('register'))

        return render_template('register.html', form=form)
    except RateLimitExceeded:
        app.logger.warning(f'Rate limit exceeded for registration from IP: {request.remote_addr}')
        return render_template('rate_limit_exceeded.html'), 429

#================================================================================================================================================================

@app.route('/dashboard')
@token_required
def dashboard(current_user):
    return render_template('dashboard.html', user=current_user)


#================================================================================================================================================================

@app.route('/deposit', methods=['GET', 'POST'])
@token_required
def deposit(current_user):
    form = DepositForm()
    if form.validate_on_submit():
        try:
            amount = form.amount.data
            amount = float(bleach.clean(str(amount), strip=True))
            current_user.balance += amount
            transaction = Transaction(user_id=current_user.id, transaction_type='Deposit',
                                      amount=amount, balance=current_user.balance)
            transaction.hash = generate_transaction_hash(transaction)
            db.session.add(transaction)
            db.session.commit()
            flash(f'Deposited {amount:.2f} successfully.', 'success')
            app.logger.info(f'User {current_user.username} deposited {amount:.2f}')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error during deposit: {str(e)}')
            flash('An error occurred during the deposit. Please try again.', 'error')
    return render_template('deposit.html', form=form)


#================================================================================================================================================================

@app.route('/withdraw', methods=['GET', 'POST'])
@token_required
def withdraw(current_user):
    form = WithdrawForm()
    if form.validate_on_submit():
        try:
            amount = form.amount.data
            amount = float(bleach.clean(str(amount), strip=True))
            if current_user.balance >= amount:
                current_user.balance -= amount
                transaction = Transaction(user_id=current_user.id, transaction_type='Withdraw',
                                          amount=-amount, balance=current_user.balance)
                transaction.hash = generate_transaction_hash(transaction)
                db.session.add(transaction)
                db.session.commit()
                flash(f'Withdrawn {amount:.2f} successfully.', 'success')
                app.logger.info(f'User {current_user.username} withdrew {amount:.2f}')
            else:
                flash('Insufficient funds.', 'error')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error during withdrawal: {str(e)}')
            flash('An error occurred during the withdrawal. Please try again.', 'error')
    return render_template('withdraw.html', form=form)

#================================================================================================================================================================

@app.route('/transactions')
@token_required
def transactions(current_user):
    user_transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date.desc()).all()
    for transaction in user_transactions:
        if not verify_transaction_integrity(transaction):
            flash('Warning: Some transactions may have been tampered with.', 'error')
            app.logger.warning(f'Transaction integrity check failed for transaction ID: {transaction.id}')
            break
    return render_template('transactions.html', transactions=user_transactions)


#================================================================================================================================================================

@app.route('/loan', methods=['GET', 'POST'])
@token_required
def loan(current_user):
    form = LoanForm()
    if form.validate_on_submit():
        try:
            amount = form.amount.data
            amount = float(bleach.clean(str(amount), strip=True))
            years = form.years.data
            loan_type = form.loan_type.data

            interest_rates = {
                'education': 0.01,
                'car': 0.06,
                'home': 0.02,
                'personal': 0.08
            }
            interest_rate = interest_rates.get(loan_type)
            if interest_rate is None:
                flash('Invalid loan type.', 'error')
                return redirect(url_for('loan'))

            monthly_rate = interest_rate / 12
            months = years * 12
            monthly_payment = (amount * monthly_rate * (1 + monthly_rate) ** months) / ((1 + monthly_rate) ** months - 1)

            current_user.balance += amount
            current_user.loan_amount += amount
            transaction = Transaction(user_id=current_user.id, transaction_type='Loan',
                                      amount=amount, balance=current_user.balance)
            transaction.hash = generate_transaction_hash(transaction)
            db.session.add(transaction)
            db.session.commit()

            flash(f'Loan of {amount:.2f} approved. Monthly payment: {monthly_payment:.2f}', 'success')
            app.logger.info(f'User {current_user.username} took a loan of {amount:.2f}')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error during loan application: {str(e)}')
            flash('An error occurred during the loan application. Please try again.', 'error')

    return render_template('loan.html', form=form)


#================================================================================================================================================================

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)


#================================================================================================================================================================

@app.route('/admin/create_user', methods=['GET', 'POST'])
@admin_required
def admin_create_user():
    form = AdminCreateUserForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email address already in use. Please use a different email.', 'error')
            return redirect(url_for('admin_create_user'))

        try:
            hashed_password = generate_password_hash(form.password.data)
            new_user = User(
                username=form.username.data,
                password=hashed_password,
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                phone=form.phone.data,
                city=form.city.data,
                email=form.email.data,
                account_type=form.account_type.data,
                age=form.age.data,
                is_admin=form.is_admin.data
            )
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully.', 'success')
            app.logger.info(f'Admin created new user: {form.username.data}')
            return redirect(url_for('admin_dashboard'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('admin_create_user'))

    return render_template('admin_create_user.html', form=form)


#================================================================================================================================================================

@app.route('/profile')
@token_required
def profile(current_user):
    return render_template('profile.html', user=current_user)


#================================================================================================================================================================

@app.route('/change_password', methods=['GET', 'POST'])
@token_required
def change_password(current_user):
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not check_password_hash(current_user.password, old_password):
            flash('Current password is incorrect.', 'error')
        elif new_password != confirm_password:
            flash('New passwords do not match.', 'error')
        elif len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
        else:
            current_user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Password changed successfully.', 'success')
            app.logger.info(f'User {current_user.username} changed their password')
            return redirect(url_for('profile'))

    return render_template('change_password.html')

#================================================================================================================================================================

@app.route('/audit_log')
@admin_required
def audit_log():
    logs = []
    with open('logs/hamadabank.log', 'r') as log_file:
        logs = log_file.readlines()
    return render_template('audit_log.html', logs=logs)

#================================================================================================================================================================

@app.route('/api/balance')
@token_required
def get_balance(current_user):
    return jsonify({'balance': current_user.balance})


#================================================================================================================================================================


def generate_transaction_hash(transaction):
    """Generate a hash for the transaction to ensure integrity."""
    data = f"{transaction.user_id}{transaction.transaction_type}{transaction.amount}{transaction.balance}{transaction.date}"
    return generate_password_hash(data)


#================================================================================================================================================================


def verify_transaction_integrity(transaction):
    """Verify the integrity of a transaction by checking its hash."""
    data = f"{transaction.user_id}{transaction.transaction_type}{transaction.amount}{transaction.balance}{transaction.date}"
    return check_password_hash(transaction.hash, data)


#================================================================================================================================================================


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

#================================================================================================================================================================

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500


#================================================================================================================================================================
@app.route('/api/admin/logs')
@admin_required
def get_logs():
    try:
        logs = []
        log_files = glob.glob('logs/hamadabank.log*')
        
        app.logger.debug(f"Found log files: {log_files}")

        for log_file_path in sorted(log_files, key=os.path.getmtime, reverse=True):
            with open(log_file_path, 'r') as log_file:
                for line in log_file:
                    match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) (\w+): (.+) \[in .+\]', line)
                    if match:
                        timestamp, level, message = match.groups()
                        
                        # Extract IP, UserAgent, Method, and Path from the message
                        ip_match = re.search(r'IP=([\d\.]+)', message)
                        method_match = re.search(r'Method=(\w+)', message)
                        path_match = re.search(r'Path=(/[^\s]+)', message)
                        
                        log_entry = {
                            'timestamp': timestamp,
                            'level': level,
                            'message': message,
                            'ip': ip_match.group(1) if ip_match else 'N/A',
                            'method': method_match.group(1) if method_match else None,
                            'path': path_match.group(1) if path_match else None
                        }
                        logs.append(log_entry)

        # Sort logs by timestamp (newest first)
        sorted_logs = sorted(logs, key=lambda x: datetime.strptime(x['timestamp'], '%Y-%m-%d %H:%M:%S,%f'), reverse=True)

        app.logger.debug(f"Returning {len(sorted_logs)} log entries")
        return jsonify(sorted_logs)
    except Exception as e:
        app.logger.error(f"Error in get_logs: {str(e)}")
        return jsonify({"error": "An error occurred while fetching logs"}), 500


#================================================================================================================================================================

# @app.before_request
# def before_request():
#     if not request.is_secure:
#         url = request.url.replace('http://', 'https://', 1)
#         code = 301
#         return redirect(url, code=code)


#================================================================================================================================================================

if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists('Hamadabank.db'):
            print("Database does not exist. Creating new database...")
            db.create_all()
            recreate_database()
        else:
            try:
                User.query.first()
            except Exception as e:
                if 'no such column: user.is_admin' in str(e):
                    print("Updating database schema...")
                    recreate_database()
                else:
                    raise e
                

    app.run(debug=False, host='0.0.0.0', port=5000)  # Run without SSL

    # app.run(debug=False, host='0.0.0.0', port=5000)  # Run without SSL
    # app.run(debug=False, ssl_context='adhoc')  # Use 'adhoc' for development, proper SSL cert for production
    # app.run(debug=False, port=5000)  # Change the port if necessary

from flask import Flask
from flask import render_template
import json
from pathlib import Path
from flask import request, redirect, url_for, flash, session, abort, send_file
import re
import config
import bcrypt
import logging
import time
from functools import wraps
import io
import os
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config.from_object(config.Config)
cipher_suite = Fernet(app.config['ENCRYPTION_KEY'])

logging.basicConfig(
    filename=config.Config.SECURITY_LOG, 
    level=logging.INFO, 
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

USERS_FILE = config.Config.USERS_FILE

def load_users_from_file():
    path = Path(USERS_FILE)
    if not path.exists():
        return {}    
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}
    
def save_user_to_file(user_data):
    Path(USERS_FILE).parent.mkdir(parents=True, exist_ok=True)
    users = load_users_from_file()
    users[user_data['username']] = user_data
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def check_username_requirements(username):
    if re.match(r'^[\w]{3,20}$', username):
        return True
    return False

def check_email_requirements(email):
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return True
    return False

def check_pw_requirements(password):
    if len(password) < 12:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    allowed_special_characters = set("!@#$%^&*")
    has_special_character = any(c in allowed_special_characters for c in password)
    return has_upper and has_lower and has_digit and has_special_character

def require_role(*role_names):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # check if they're logged in
            if 'username' not in session:
                logging.warning("Unauthorized access attempt: No active session.")
                flash("Please log in to view this page", "danger")
                return redirect(url_for('login'))
            
            # improper role action
            user_role = session.get('role')
            if user_role not in role_names:
                logging.warning(f"Access Denied: User '{session['username']}' with role '{user_role}' tried to access a restricted area.")
                abort(403)
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.before_request
def check_session_timeout():
    session.permanent = True 
    if 'username' in session:
        session.modified = True

# app routes
@app.route("/")
def home():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not check_username_requirements(username): 
            flash("Invalid username requirements", "danger")
            return render_template("signup.html", username=username, email=email)
            
        if not check_email_requirements(email): 
            flash("Invalid email requirements", "danger")
            return render_template("signup.html", username=username, email=email)
            
        if not check_pw_requirements(password): 
            flash("Invalid password requirements", "danger")
            return render_template("signup.html", username=username, email=email)
            
        if password != confirm_password:
            flash("Passwords don't match", "danger")
            return render_template("signup.html", username=username, email=email)
        
        users = load_users_from_file()
        if username in users:
            flash("Try Again. Username or email already in use.", "danger")
            logging.warning(f"Failed registration: Duplicate username attempt ({username})")
            return render_template("signup.html", username=username, email=email)
            
        for existing_user in users.values():
            if existing_user.get('email') == email:
                flash("Try Again. Username or email already in use.", "danger")
                logging.warning(f"Failed registration: Duplicate email attempt ({email})")
                return render_template("signup.html", username=username, email=email)
      
        pw_string_to_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=12) 
        hashed_password_bytes = bcrypt.hashpw(pw_string_to_bytes, salt)

        new_user = {
            "username": username,
            "email": email,
            "password_hash": hashed_password_bytes.decode('utf-8'),
            "created_at": time.time(),
            "role": "User",          
            "failed_attempts": 0,    
            "locked_until": None
        }
        
        save_user_to_file(new_user)
        flash("Account created successfully!", "success")
        logging.info(f"Successful registration: User '{username}' created.")
        return redirect(url_for('login')) 
    
    # on GET request
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        users = load_users_from_file()
        user_data = users.get(username)

        if user_data.get('locked_until'):
            if time.time() < user_data['locked_until']:
                logging.warning(f"Login denied: Account '{username}' is currently locked.")
                flash("Account locked. Please try again later.", "danger")
                return render_template("login.html")

        if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data['password_hash'].encode('utf-8')): # success case
            user_data['failed_attempts'] = 0
            user_data['locked_until'] = None
            save_user_to_file(user_data)
                
            session.clear()
            session['username'] = username
            session['role'] = user_data.get('role', 'User')

            session.permanent = True
            
            logging.info(f"Successful login: User '{username}'")
            flash("Welcome back!", "success")
            return redirect(url_for('dashboard'))
            
        else:
            if user_data:
                user_data['failed_attempts'] += 1
                if user_data['failed_attempts'] >= 5:
                    user_data['locked_until'] = time.time() + 900
                    logging.warning(f"ACCOUNT_LOCKED: User '{username}' after 5 failed attempts.")
                    flash("Too many failed attempts. Account locked for 15 minutes.", "danger")
                else:
                    logging.warning(f"Failed login attempt ({user_data['failed_attempts']}/5): User '{username}'")
                    flash("Invalid username or password", "danger")
                save_user_to_file(user_data)
            else:
                flash("Invalid username or password", "danger")
            return render_template("login.html", username=username)

    return render_template("login.html")

@app.route("/logout")
def logout():
    username = session.get('username')
    session.clear()
    logging.info(f"User '{username}' logged out.")
    flash("You have been logged out", "success")
    return redirect(url_for('login'))

# rbac routes
@app.route("/dashboard")
@require_role('Admin', 'User')
def dashboard():
    return render_template("dashboard.html", username=session['username'], role=session['role'])

@app.route("/admin_dashboard")
@require_role('Admin')
def admin_dashboard():
    users = load_users_from_file()
    log_entries = []
    log_path = app.config['SECURITY_LOG']
    
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            log_entries = f.readlines()[-50:]
            # reversed so newest events are at the top
            log_entries.reverse()

    return render_template("admin_dashboard.html", users=users, logs=log_entries)

@app.route("/upload", methods=['GET', 'POST'])
@require_role('Admin', 'User')
def upload_page():
    if request.method == 'POST':
        file = request.files.get('document')
        if not file or file.filename == '':
            flash("No file selected", "danger")
            return redirect(request.url)
        
        filename = secure_filename(file.filename)
        
        file_data = file.read()
        encrypted_data = cipher_suite.encrypt(file_data)

        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}.enc")
        with open(upload_path, 'wb') as f:
            f.write(encrypted_data)
            
        logging.info(f"FILE_UPLOAD: User '{session['username']}' uploaded '{filename}'")
        flash("File uploaded successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template("upload.html")

@app.route("/view_files")
@require_role('Admin', 'User', 'Guest') # everybody allowed 
def view_files():
    upload_path = app.config['UPLOAD_FOLDER']

    if not os.path.exists(upload_path):
        os.makedirs(upload_path)
    files = [f for f in os.listdir(upload_path) if f.endswith('.enc')]

    return render_template("view_files.html", files=files)

@app.route("/download/<filename>")
@require_role('Admin', 'User', 'Guest')
def download_file(filename):
    # secure_filename() cleans up filename 
    safe_filename = secure_filename(filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    
    if not os.path.exists(file_path):
        logging.error(f"DOWNLOAD_FAIL: File {safe_filename} not found.")
        abort(404)

    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = cipher_suite.decrypt(encrypted_data)
        original_name = safe_filename.replace('.enc', '')

        logging.info(f"FILE_DOWNLOAD: User '{session.get('username')}'downloaded '{original_name}'")
        
        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=original_name,
            mimetype='application/octet-stream'
        )

    except Exception as e:
        logging.error(f"DECRYPTION_FAIL: Error processing {safe_filename}: {str(e)}")
        flash("Integrity check failed. File may be corrupted or key is invalid.", "danger")
        return redirect(url_for('view_files'))
    
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
    return response

if __name__ == "__main__":
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))
from flask import Flask
from flask import render_template
import json
from pathlib import Path
from flask import request, redirect, url_for, flash
import re
import config
import bcrypt
import logging
import time

app = Flask(__name__)
app.config.from_object(config.Config)

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
        return redirect(url_for('home')) 
    
    # on GET request
    return render_template("signup.html")

@app.route("/")
def home():
    return render_template("login.html")

if __name__ == "__main__":
    app.run(debug = True)
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Config:
    BASE_DIR = Path(__file__).resolve().parent
    DATA_DIR = BASE_DIR / "data"
    LOG_DIR = BASE_DIR / "logs"
    
    USERS_FILE = DATA_DIR / "users.json"
    SECURITY_LOG = LOG_DIR / "security.log"
   
    SECRET_KEY = os.environ["SECRET_KEY"] # must exist; crash if missing
    BCRYPT_LOG_ROUNDS = 12

    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
    UPLOAD_FOLDER = BASE_DIR / "data" / "uploads"
    
    PERMANENT_SESSION_LIFETIME = 1800  # 30 min
    SESSION_COOKIE_HTTPONLY = True 
    SESSION_COOKIE_SECURE = True 
    SESSION_COOKIE_SAMESITE = 'Strict' 
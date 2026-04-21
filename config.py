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
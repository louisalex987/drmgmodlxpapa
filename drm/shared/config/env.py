from dotenv import load_dotenv
from pathlib import Path
import os 

load_dotenv(Path(__file__).resolve().parent.parent.parent / '.env')

def env():
    return {
        "DB_PATH": os.getenv("DB_PATH", "data/app.db"),
        "API_KEY": os.getenv("API_KEY"),
        "ADMIN_HASH": os.getenv("ADMIN_HASH"),
        "FLASK_SECRET": os.getenv("FLASK_SECRET", "change_me"),
    }
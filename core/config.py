# V_scanner/core/config.py

import os
from dotenv import load_dotenv
from pathlib import Path

env_path = Path(__file__).resolve().parent.parent / '.env'
load_dotenv(dotenv_path=env_path)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
COHERE_API_KEY = os.getenv("COHERE_API_KEY")

class Config:
    """Central configuration for the scanner."""
    TIMEOUT = 10
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) Firefox/89.0"
    ]
    API_PORT = int(os.getenv("API_PORT", "8765"))
    API_HOST = os.getenv("API_HOST", "0.0.0.0")

def get_config():
    """Returns an instance of the configuration class."""
    return Config()

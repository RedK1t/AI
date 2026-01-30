# V_scanner/core/config.py

GEMINI_API_KEY ="AIzaSyAkWb8H26iMdYA_PxI5W5pPeSjS2Q4nNhE"
COHERE_API_KEY = "pc5OuQ6F4KuhIk9OIJTUkgLDSwaJfagP404swBXM"
class Config:
    """Central configuration for the scanner."""
    TIMEOUT = 10
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) Firefox/89.0"
    ]
def get_config():
    """Returns an instance of the configuration class."""
    return Config()

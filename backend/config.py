import os
from datetime import timedelta

class Config:
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")

    # Cookie session config
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True

    # File upload config
    UPLOAD_PATH = os.environ.get("UPLOAD_PATH")
    UPLOAD_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.pdf']
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024 # 16MB

    # Login and register config
    MAX_FAILED_LOGIN_ATTEMPTS = 3
    AMOUNT_OF_CHARS_REQUIRED_IN_PASSWORD = 6
    LOGIN_TIMEOUT = 2

    AMOUNT_OF_COMBINATIONS_GENERATED_FOR_PASSWORD = 10
    REGISTER_TIMEOUT = 2



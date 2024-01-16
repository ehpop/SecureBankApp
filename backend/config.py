import os
from datetime import timedelta

class Config:
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL",
                                             "postgresql://database_admin:b8d0e9de879f42b9c7f88b0151bc3e182806b6d5be3e8ed448ca518c558e2d0e@localhost:5432/bank_prod_db")
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "very secret key")

    # Cookie session config
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True

    # File upload config
    UPLOAD_PATH = os.environ.get("UPLOAD_PATH")
    UPLOAD_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.pdf']
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2MB, max size used for request
    MAX_PIL_IMAGE_PIXELS = 16 * 1024 * 1024  # 4000 x 4000 pixels, max size used for PIL


    # Login and register config
    MAX_FAILED_LOGIN_ATTEMPTS = 3
    AMOUNT_OF_CHARS_REQUIRED_IN_PASSWORD = 6
    AMOUNT_OF_COMBINATIONS_GENERATED_FOR_PASSWORD = 10

    # Timeout config (time in seconds)
    LOGIN_TIMEOUT = 2
    REGISTER_TIMEOUT = 2
    CHANGE_PASSWORD_TIMEOUT = 2
    PASSWORD_RECOVERY_TIMEOUT = 2

    # Password recovery
    TIME_ALLOWED_FOR_PASSWORD_RECOVERY = 5  # minutes
    PASSWORD_RECOVERY_CODE_LENGTH = 32

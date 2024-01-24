import os
from datetime import timedelta


class Config:
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL",
                                             "postgresql://postgres:postgres@localhost:5432/postgres")
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "very secret key")

    # Cookie session config
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # File upload config
    UPLOAD_PATH = os.environ.get("UPLOAD_PATH", "test/uploads")
    UPLOAD_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.pdf']
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2MB, max size used for request
    MAX_PIL_IMAGE_PIXELS = 16 * 1024 * 1024  # 4000 x 4000 pixels, max size used for PIL

    # Login and register config
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 16
    MAX_FAILED_LOGIN_ATTEMPTS = 3
    FAILED_LOGIN_ATTEMPTS_LOCKOUT_TIME = 5  # minutes
    AMOUNT_OF_CHARS_REQUIRED_IN_PASSWORD = 6
    AMOUNT_OF_COMBINATIONS_GENERATED_FOR_PASSWORD = 10
    AMOUNT_OF_TIME_PASSWORD_COMBINATION_IS_ACTIVE = 10  # minutes
    DEFAULT_USER_BALANCE = 1000  # we are secure, yet terrible bank

    # Timeout config (time in seconds)
    LOGIN_TIMEOUT = 2
    REGISTER_TIMEOUT = 2
    CHANGE_PASSWORD_TIMEOUT = 2
    PASSWORD_RECOVERY_TIMEOUT = 2

    # Password recovery
    TIME_ALLOWED_FOR_PASSWORD_RECOVERY = 5  # minutes
    PASSWORD_RECOVERY_CODE_LENGTH = 32

    # Bcrypt config
    BCRYPT_LOG_WORK_FACTOR = 13

    # AES config
    AES_KEY_LENGTH = 32
    AES_PADDING_STYLE = 'x923'

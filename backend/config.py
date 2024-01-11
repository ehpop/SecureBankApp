import os
from datetime import timedelta

class Config:
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")

    # Cookie session config
    SESSION_COOKIE_SECURE = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    # File upload config
    UPLOAD_PATH = os.environ.get("UPLOAD_FOLDER")
    UPLOAD_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.pdf']
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024 # 16MB



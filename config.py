import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
    # التعديل الأساسي: القراءة من DATABASE_URL، مع الاحتفاظ بـ SQLite كخيار احتياطي للتطوير المحلي
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///anonapp.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    FERNET_KEY = os.getenv("FERNET_KEY")
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")
    OTP_TTL_SECONDS = 300
    SHOW_OTP_ON_SCREEN = os.getenv("SHOW_OTP_ON_SCREEN", "False").lower() == "true"
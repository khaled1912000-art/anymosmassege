from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def utcnow():
    return datetime.now(timezone.utc)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone_encrypted = db.Column(db.String(512), nullable=False)
    phone_hash = db.Column(db.String(64), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=utcnow)

class OtpCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

class Confession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(64), nullable=False)
    confession_id = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=utcnow)
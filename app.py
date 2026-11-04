import os
import re
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort
)
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import check_password_hash

from config import Config
from models import db, User, OtpCode, Confession, AuditLog

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

fernet = Fernet(app.config["FERNET_KEY"].encode())

PHONE_RE = re.compile(r"^07\d{8}$")

def encrypt_phone(phone: str) -> str:
    return fernet.encrypt(phone.encode()).decode()

def decrypt_phone(token: str) -> str:
    try:
        return fernet.decrypt(token.encode()).decode()
    except (InvalidToken, AttributeError):
        return "—"

def hash_phone(phone: str) -> str:
    return hashlib.sha256(phone.encode()).hexdigest()

def get_client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()

def get_csrf_token() -> str:
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]

def validate_csrf():
    token = request.form.get("_csrf", "")
    expected = session.get("_csrf", "")
    if not expected or not secrets.compare_digest(token, expected):
        abort(400, description="CSRF token invalid")

app.jinja_env.globals["csrf_token"] = get_csrf_token

_attempts = {}

def rate_limit(key: str, limit: int, window_seconds: int) -> bool:
    now = datetime.now(timezone.utc)
    arr = [t for t in _attempts.get(key, []) if (now - t).total_seconds() < window_seconds]
    if len(arr) >= limit:
        _attempts[key] = arr
        return False
    arr.append(now)
    _attempts[key] = arr
    return True

def log_event(action: str, confession_id=None, extra: str = ""):
    db.session.add(AuditLog(
        action=action,
        confession_id=confession_id,
        timestamp=datetime.now(timezone.utc),
    ))
    db.session.commit()
    print(f"[AUDIT] {action} | ip={get_client_ip()} | {extra}")

def reset_session_keep_csrf():
    csrf = session.get("_csrf")
    session.clear()
    if csrf:
        session["_csrf"] = csrf

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        validate_csrf()

        if not rate_limit(f"otp:{get_client_ip()}", limit=5, window_seconds=600):
            flash("محاولات كثيرة. حاول لاحقاً.", "error")
            return redirect(url_for("index"))

        phone = (request.form.get("phone") or "").strip()
        if not PHONE_RE.match(phone):
            flash("الرقم يجب أن يكون 10 أرقام ويبدأ بـ 07", "error")
            return redirect(url_for("index"))

        user = User.query.filter_by(phone_hash=hash_phone(phone)).first()
        if not user:
            user = User(
                phone_encrypted=encrypt_phone(phone),
                phone_hash=hash_phone(phone),
            )
            db.session.add(user)
            db.session.commit()

        OtpCode.query.filter_by(user_id=user.id, used=False).update({"used": True})

        code = f"{secrets.randbelow(1_000_000):06d}"
        otp = OtpCode(
            user_id=user.id,
            code=code,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=app.config["OTP_TTL_SECONDS"]),
        )
        db.session.add(otp)
        db.session.commit()

        print(f"[OTP] رقم {phone[-4:]} → الرمز: {code}")

        reset_session_keep_csrf()
        session["pending_user_id"] = user.id
        if app.config["SHOW_OTP_ON_SCREEN"]:
            session["dev_otp"] = code
        session.permanent = True
        return redirect(url_for("verify"))

    return render_template("index.html")

@app.route("/verify", methods=["GET", "POST"])
def verify():
    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect(url_for("index"))

    if request.method == "POST":
        validate_csrf()

        if not rate_limit(f"verify:{get_client_ip()}", limit=10, window_seconds=600):
            flash("محاولات كثيرة. حاول لاحقاً.", "error")
            return redirect(url_for("index"))

        entered = (request.form.get("code") or "").strip()
        if not re.fullmatch(r"\d{6}", entered):
            flash("رمز غير صالح", "error")
            return redirect(url_for("verify"))

        otp = (
            OtpCode.query.filter_by(user_id=user_id, used=False)
            .order_by(OtpCode.id.desc())
            .first()
        )
        if not otp:
            flash("انتهت صلاحية الرمز، أعد المحاولة", "error")
            return redirect(url_for("index"))

        expires = otp.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < datetime.now(timezone.utc):
            flash("انتهت صلاحية الرمز، أعد المحاولة", "error")
            return redirect(url_for("index"))

        if not secrets.compare_digest(otp.code, entered):
            flash("رمز خاطئ", "error")
            return redirect(url_for("verify"))

        otp.used = True
        db.session.commit()

        reset_session_keep_csrf()
        session["user_id"] = user_id
        session.permanent = True
        return redirect(url_for("confession"))

    dev_otp = session.get("dev_otp") if app.config["SHOW_OTP_ON_SCREEN"] else None
    return render_template("verify.html", dev_otp=dev_otp)

@app.route("/confession", methods=["GET", "POST"])
def confession():
    if "user_id" not in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        validate_csrf()

        if not rate_limit(f"conf:{session['user_id']}", limit=10, window_seconds=3600):
            flash("تجاوزت الحد المسموح. حاول بعد ساعة.", "error")
            return redirect(url_for("confession"))

        message = (request.form.get("message") or "").strip()
        if not (3 <= len(message) <= 2000):
            flash("الرسالة يجب أن تكون بين 3 و2000 حرف", "error")
            return redirect(url_for("confession"))

        db.session.add(Confession(user_id=session["user_id"], message=message))
        db.session.commit()
        log_event("new_confession", extra=f"user_id={session['user_id']}")
        flash("تم إرسال صراحتك", "success")
        return redirect(url_for("confession"))

    return render_template("confession.html")

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapper

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        validate_csrf()

        if not rate_limit(f"admin_login:{get_client_ip()}", limit=5, window_seconds=900):
            flash("محاولات كثيرة. حاول لاحقاً.", "error")
            return redirect(url_for("admin_login"))

        u = (request.form.get("username") or "").strip()
        p = request.form.get("password") or ""

        stored_user = app.config.get("ADMIN_USERNAME") or ""
        stored_hash = app.config.get("ADMIN_PASSWORD_HASH") or ""

        print(f"[DEBUG] u={u!r} p_len={len(p)} hash_len={len(stored_hash)}")

        user_ok = secrets.compare_digest(u.encode(), stored_user.encode())
        pass_ok = False
        if stored_hash:
            try:
                pass_ok = check_password_hash(stored_hash, p)
            except Exception as e:
                print(f"[DEBUG] check_password_hash error: {e}")

        print(f"[DEBUG] user_ok={user_ok} pass_ok={pass_ok}")

        if user_ok and pass_ok:
            reset_session_keep_csrf()
            session["is_admin"] = True
            session.permanent = True
            log_event("admin_login_success")
            return redirect(url_for("admin_dashboard"))

        log_event("admin_login_fail", extra=f"user={u}")
        flash("بيانات دخول خاطئة", "error")

    return render_template("admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    reset_session_keep_csrf()
    return redirect(url_for("admin_login"))

@app.route("/admin")
@admin_required
def admin_dashboard():
    confessions = Confession.query.order_by(Confession.id.desc()).all()
    rows = []
    for c in confessions:
        user = db.session.get(User, c.user_id)
        rows.append({
            "id": c.id,
            "message": c.message,
            "created_at": c.created_at,
            "phone": decrypt_phone(user.phone_encrypted) if user else "—",
        })
        db.session.add(AuditLog(
            action="view_phone",
            confession_id=c.id,
            timestamp=datetime.now(timezone.utc),
        ))
    db.session.commit()
    return render_template("admin_dashboard.html", rows=rows)

@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", message=getattr(e, "description", "طلب غير صالح")), 400

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", message="الصفحة غير موجودة"), 404

@app.errorhandler(429)
def too_many(e):
    return render_template("error.html", message="محاولات كثيرة"), 429

import os

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
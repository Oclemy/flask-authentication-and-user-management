import os
import re
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify, render_template, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt as pyjwt

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
app = Flask(__name__)
CORS(app, supports_credentials=True)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-in-production")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "sqlite:///users.db"
)
# Railway Postgres URLs start with postgres:// but SQLAlchemy needs postgresql://
if app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgres://"):
    app.config["SQLALCHEMY_DATABASE_URI"] = app.config[
        "SQLALCHEMY_DATABASE_URI"
    ].replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_EXPIRY_HOURS"] = int(os.getenv("JWT_EXPIRY_HOURS", "24"))

db = SQLAlchemy(app)

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    display_name = db.Column(db.String(120), default="")
    bio = db.Column(db.Text, default="")
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self, private=False):
        data = {
            "id": self.id,
            "username": self.username,
            "display_name": self.display_name,
            "bio": self.bio,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if private:
            data.update(
                {
                    "email": self.email,
                    "is_active": self.is_active,
                    "is_admin": self.is_admin,
                    "updated_at": self.updated_at.isoformat()
                    if self.updated_at
                    else None,
                }
            )
        return data


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------
def create_token(user: User) -> str:
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "is_admin": user.is_admin,
        "exp": datetime.now(timezone.utc)
        + timedelta(hours=app.config["JWT_EXPIRY_HOURS"]),
        "iat": datetime.now(timezone.utc),
    }
    return pyjwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")


def get_current_user():
    """Extract user from Authorization header or cookie."""
    token = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
    if not token:
        token = request.cookies.get("token")
    if not token:
        return None
    try:
        data = pyjwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        return db.session.get(User, int(data["sub"]))
    except (pyjwt.ExpiredSignatureError, pyjwt.InvalidTokenError):
        return None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        if not user.is_active:
            return jsonify({"error": "Account deactivated"}), 403
        request.user = user
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not request.user.is_admin:
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_registration(data):
    errors = []
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""

    if len(username) < 3 or len(username) > 80:
        errors.append("Username must be 3-80 characters")
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        errors.append("Username: letters, numbers, underscores only")
    if not EMAIL_RE.match(email):
        errors.append("Invalid email")
    if len(password) < 8:
        errors.append("Password must be at least 8 characters")
    return errors


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    errors = validate_registration(data)
    if errors:
        return jsonify({"error": errors}), 400

    username = data["username"].strip()
    email = data["email"].strip().lower()

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"error": "Username or email already taken"}), 409

    user = User(username=username, email=email, display_name=username)
    user.set_password(data["password"])

    # First user becomes admin
    if User.query.count() == 0:
        user.is_admin = True

    db.session.add(user)
    db.session.commit()

    token = create_token(user)
    resp = jsonify({"message": "Registered", "user": user.to_dict(private=True), "token": token})
    resp.set_cookie("token", token, httponly=True, samesite="Lax", max_age=86400)
    return resp, 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    identifier = (data.get("username") or data.get("email") or "").strip()
    password = data.get("password") or ""

    user = User.query.filter(
        (User.username == identifier) | (User.email == identifier.lower())
    ).first()

    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401
    if not user.is_active:
        return jsonify({"error": "Account deactivated"}), 403

    token = create_token(user)
    resp = jsonify({"message": "Logged in", "user": user.to_dict(private=True), "token": token})
    resp.set_cookie("token", token, httponly=True, samesite="Lax", max_age=86400)
    return resp, 200


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    resp = jsonify({"message": "Logged out"})
    resp.delete_cookie("token")
    return resp, 200


@app.route("/api/auth/me", methods=["GET"])
@login_required
def me():
    return jsonify({"user": request.user.to_dict(private=True)})


# ---------------------------------------------------------------------------
# User profile routes
# ---------------------------------------------------------------------------
@app.route("/api/users/me", methods=["PUT"])
@login_required
def update_profile():
    data = request.get_json(silent=True) or {}
    user = request.user

    if "display_name" in data:
        user.display_name = str(data["display_name"])[:120]
    if "bio" in data:
        user.bio = str(data["bio"])[:500]
    if "email" in data:
        new_email = data["email"].strip().lower()
        if new_email != user.email:
            if not EMAIL_RE.match(new_email):
                return jsonify({"error": "Invalid email"}), 400
            if User.query.filter(User.email == new_email).first():
                return jsonify({"error": "Email taken"}), 409
            user.email = new_email

    db.session.commit()
    return jsonify({"user": user.to_dict(private=True)})


@app.route("/api/users/me/password", methods=["PUT"])
@login_required
def change_password():
    data = request.get_json(silent=True) or {}
    if not request.user.check_password(data.get("current_password", "")):
        return jsonify({"error": "Current password incorrect"}), 401
    new_pw = data.get("new_password", "")
    if len(new_pw) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    request.user.set_password(new_pw)
    db.session.commit()
    return jsonify({"message": "Password changed"})


@app.route("/api/users/me", methods=["DELETE"])
@login_required
def delete_account():
    db.session.delete(request.user)
    db.session.commit()
    resp = jsonify({"message": "Account deleted"})
    resp.delete_cookie("token")
    return resp, 200


# ---------------------------------------------------------------------------
# Public user lookup
# ---------------------------------------------------------------------------
@app.route("/api/users/<string:username>", methods=["GET"])
def get_user_public(username):
    user = User.query.filter_by(username=username).first()
    if not user or not user.is_active:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"user": user.to_dict(private=False)})


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------
@app.route("/api/admin/users", methods=["GET"])
@admin_required
def admin_list_users():
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), 100)
    q = request.args.get("q", "").strip()

    query = User.query
    if q:
        query = query.filter(
            User.username.ilike(f"%{q}%") | User.email.ilike(f"%{q}%")
        )
    pagination = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return jsonify(
        {
            "users": [u.to_dict(private=True) for u in pagination.items],
            "total": pagination.total,
            "page": page,
            "pages": pagination.pages,
        }
    )


@app.route("/api/admin/users/<int:user_id>", methods=["PUT"])
@admin_required
def admin_update_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    data = request.get_json(silent=True) or {}
    if "is_active" in data:
        user.is_active = bool(data["is_active"])
    if "is_admin" in data:
        user.is_admin = bool(data["is_admin"])
    db.session.commit()
    return jsonify({"user": user.to_dict(private=True)})


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@admin_required
def admin_delete_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user.id == request.user.id:
        return jsonify({"error": "Cannot delete yourself"}), 400
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted"})


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})


# ---------------------------------------------------------------------------
# Live demo UI
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Init DB & run
# ---------------------------------------------------------------------------
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_DEBUG", "0") == "1")

import os
import re
import secrets
import sqlite3
import time
import uuid
from collections import defaultdict, deque
from datetime import timedelta
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_socketio import SocketIO, disconnect, emit, join_room, send
from werkzeug.security import check_password_hash, generate_password_hash


USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
PASSWORD_MIN_LENGTH = 10
PASSWORD_MAX_LENGTH = 128
MAX_CHAT_LENGTH = 500
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 5
CHAT_WINDOW_SECONDS = 10
CHAT_MAX_MESSAGES = 8
TRANSFER_WINDOW_SECONDS = 60
TRANSFER_MAX_ATTEMPTS = 10
REPORT_WINDOW_SECONDS = 3600
REPORT_MAX_ATTEMPTS = 10

MAX_PRICE = 1_000_000_000
MAX_TRANSFER = 1_000_000_000
SIGNUP_BONUS = 10_000

# 신고 누적 임계값: 서로 다른 신고자 수를 기준으로 한다.
PRODUCT_BLOCK_THRESHOLD = 3
USER_SUSPEND_THRESHOLD = 5

# 이미지 업로드: 확장자가 아니라 매직 바이트로 실제 형식을 판별한다.
MAX_IMAGE_BYTES = 3 * 1024 * 1024
IMAGE_SIGNATURES = (
    (b"\xff\xd8\xff", "jpg", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "png", "image/png"),
    (b"GIF87a", "gif", "image/gif"),
    (b"GIF89a", "gif", "image/gif"),
)
ALLOWED_IMAGE_EXTS = {"jpg", "png", "gif"}
# 서버가 생성한 파일명만 허용하기 위한 형식. 경로 조작을 원천 차단한다.
IMAGE_NAME_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                           r"[0-9a-f]{4}-[0-9a-f]{12}\.(jpg|png|gif)$")

# 거래 상태 전이: requested -> accepted -> completed, 각 단계에서 cancelled 가능
TRADE_OPEN_STATUSES = ("requested", "accepted")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("MARKET_SECRET_KEY") or secrets.token_hex(32),
    DATABASE=os.environ.get("MARKET_DATABASE", "market.db"),
    UPLOAD_DIR=os.environ.get("MARKET_UPLOAD_DIR", "uploads"),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("MARKET_HTTPS", "0") == "1",
)
# cors_allowed_origins 를 비워 두면 Flask-SocketIO 가 동일 출처만 허용한다.
socketio = SocketIO(app, cors_allowed_origins=[])

login_attempts = defaultdict(deque)
chat_attempts = defaultdict(deque)
transfer_attempts = defaultdict(deque)
report_attempts = defaultdict(deque)


def get_db():
    db = getattr(g, "_database", None)
    if db is not None:
        # SocketIO 핸들러는 HTTP 요청 컨텍스트를 복사해서 실행되므로,
        # 이미 teardown 으로 닫힌 커넥션을 물려받을 수 있다. 살아있는지 확인한다.
        try:
            db.execute("SELECT 1")
        except sqlite3.ProgrammingError:
            db = None
    if db is None:
        db = g._database = sqlite3.connect(app.config["DATABASE"])
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db


@app.teardown_appcontext
def close_connection(_exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def _is_password_hash(value):
    return value.startswith(("scrypt:", "pbkdf2:"))


def _add_column_if_missing(db, table, column, definition):
    existing = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db():
    with app.app_context():
        db = get_db()
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                balance INTEGER NOT NULL DEFAULT 0,
                is_admin INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                image_name TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS trade (
                id TEXT PRIMARY KEY,
                product_id TEXT NOT NULL,
                buyer_id TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'requested',
                created_at TEXT,
                updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_type TEXT NOT NULL DEFAULT 'user',
                reason TEXT NOT NULL,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS transfer (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS message (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                actor_id TEXT,
                action TEXT NOT NULL,
                detail TEXT,
                ip TEXT,
                created_at TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_report_unique
                ON report (reporter_id, target_id);
            CREATE INDEX IF NOT EXISTS idx_message_pair
                ON message (sender_id, receiver_id);
            CREATE INDEX IF NOT EXISTS idx_trade_product
                ON trade (product_id, status);
            """
        )
        os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)

        # 기존 실습 DB 스키마와의 호환을 위한 마이그레이션.
        _add_column_if_missing(db, "user", "balance", "INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(db, "user", "is_admin", "INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(db, "user", "is_active", "INTEGER NOT NULL DEFAULT 1")
        _add_column_if_missing(db, "user", "created_at", "TEXT")
        _add_column_if_missing(db, "product", "status", "TEXT NOT NULL DEFAULT 'active'")
        _add_column_if_missing(db, "product", "image_name", "TEXT")
        _add_column_if_missing(db, "product", "created_at", "TEXT")
        _add_column_if_missing(db, "report", "target_type", "TEXT NOT NULL DEFAULT 'user'")
        _add_column_if_missing(db, "report", "created_at", "TEXT")

        # 기존 실습 DB의 평문 비밀번호를 앱 시작 시 한 번 해시로 마이그레이션한다.
        for user in db.execute("SELECT id, password FROM user").fetchall():
            if not _is_password_hash(user["password"]):
                db.execute(
                    "UPDATE user SET password = ? WHERE id = ?",
                    (generate_password_hash(user["password"]), user["id"]),
                )
        db.commit()
        _bootstrap_admin(db)


def _bootstrap_admin(db):
    """관리자 계정은 코드가 아닌 환경 변수로만 생성/승격한다."""
    username = os.environ.get("MARKET_ADMIN_USERNAME", "").strip()
    password = os.environ.get("MARKET_ADMIN_PASSWORD", "")
    if not username or not password:
        return
    if not USERNAME_RE.fullmatch(username) or len(password) < PASSWORD_MIN_LENGTH:
        return
    row = db.execute("SELECT id FROM user WHERE username = ?", (username,)).fetchone()
    if row:
        db.execute("UPDATE user SET is_admin = 1, is_active = 1 WHERE id = ?", (row["id"],))
    else:
        db.execute(
            "INSERT INTO user (id, username, password, balance, is_admin, is_active, created_at) "
            "VALUES (?, ?, ?, 0, 1, 1, datetime('now'))",
            (str(uuid.uuid4()), username, generate_password_hash(password)),
        )
    db.commit()


def audit(action, detail="", actor_id=None):
    """감사 로그. 비밀번호 등 민감 값은 절대 detail 로 넘기지 않는다."""
    get_db().execute(
        "INSERT INTO audit_log (id, actor_id, action, detail, ip, created_at) "
        "VALUES (?, ?, ?, ?, ?, datetime('now'))",
        (
            str(uuid.uuid4()),
            actor_id if actor_id is not None else session.get("user_id"),
            action,
            detail[:500],
            request.remote_addr,
        ),
    )


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return get_db().execute(
        "SELECT id, username, bio, balance, is_admin, is_active FROM user WHERE id = ?",
        (user_id,),
    ).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        # 관리자 여부는 세션이 아닌 DB 값으로 매 요청 확인한다(권한 상승 방지).
        if not user["is_admin"]:
            audit("admin_access_denied", request.path)
            get_db().commit()
            abort(404)
        return view(*args, **kwargs)

    return wrapped


def _valid_uuid(value):
    try:
        uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return False
    return True


def _client_key(username=""):
    return f"{request.remote_addr or 'unknown'}:{username.casefold()}"


def _rate_limited(bucket, key, limit, window):
    now = time.monotonic()
    attempts = bucket[key]
    while attempts and now - attempts[0] > window:
        attempts.popleft()
    if len(attempts) >= limit:
        return True
    attempts.append(now)
    return False


def _new_csrf_token():
    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    return token


@app.context_processor
def template_context():
    user = current_user() if "user_id" in session else None
    return {
        "csrf_token": session.get("csrf_token") or _new_csrf_token(),
        "current_user": user,
    }


@app.before_request
def enforce_session_and_csrf():
    now = int(time.time())
    if "user_id" in session:
        created_at = session.get("created_at", now)
        last_seen = session.get("last_seen", now)
        if now - created_at > 8 * 60 * 60 or now - last_seen > 30 * 60:
            session.clear()
            flash("세션이 만료되었습니다. 다시 로그인해 주세요.")
            return redirect(url_for("login"))
        session["last_seen"] = now

        # 휴면(정지) 처리된 계정은 기존 세션도 즉시 무효화한다.
        row = get_db().execute(
            "SELECT is_active FROM user WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if row is None or not row["is_active"]:
            session.clear()
            flash("이용이 제한된 계정입니다. 관리자에게 문의해 주세요.")
            return redirect(url_for("login"))

    if request.method == "POST":
        expected = session.get("csrf_token", "")
        supplied = request.form.get("csrf_token", "")
        if not expected or not secrets.compare_digest(expected, supplied):
            abort(400, description="잘못된 요청입니다.")


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self' ws: wss:; object-src 'none'; base-uri 'self'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
@app.errorhandler(429)
def safe_client_error(error):
    messages = {
        400: "요청 형식이 올바르지 않습니다.",
        403: "접근 권한이 없습니다.",
        404: "요청한 페이지를 찾을 수 없습니다.",
        413: "요청 데이터가 너무 큽니다.",
        429: "요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.",
    }
    return render_template("error.html", message=messages[error.code]), error.code


@app.errorhandler(500)
def internal_error(_error):
    # 스택 트레이스/DB 오류 원문을 사용자에게 노출하지 않는다.
    return render_template("error.html", message="서버 오류가 발생했습니다."), 500


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


# ---------------------------------------------------------------- 사용자 관리

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not USERNAME_RE.fullmatch(username):
            flash("아이디는 영문, 숫자, 밑줄로 이루어진 3~20자여야 합니다.")
            return redirect(url_for("register"))
        if not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
            flash(f"비밀번호는 {PASSWORD_MIN_LENGTH}~{PASSWORD_MAX_LENGTH}자여야 합니다.")
            return redirect(url_for("register"))

        db = get_db()
        # 계정 열거를 막기 위해 중복/실패 메시지를 동일하게 유지한다.
        if db.execute("SELECT 1 FROM user WHERE username = ?", (username,)).fetchone():
            flash("사용할 수 없는 아이디입니다.")
            return redirect(url_for("register"))
        user_id = str(uuid.uuid4())
        try:
            db.execute(
                "INSERT INTO user (id, username, password, balance, is_admin, is_active, created_at) "
                "VALUES (?, ?, ?, ?, 0, 1, datetime('now'))",
                (user_id, username, generate_password_hash(password), SIGNUP_BONUS),
            )
            audit("register", f"username={username}", actor_id=user_id)
            db.commit()
        except sqlite3.IntegrityError:
            flash("사용할 수 없는 아이디입니다.")
            return redirect(url_for("register"))
        flash("회원가입이 완료되었습니다. 로그인해 주세요.")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        key = _client_key(username)
        if _rate_limited(login_attempts, key, LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_SECONDS):
            abort(429)

        db = get_db()
        user = db.execute(
            "SELECT * FROM user WHERE username = ?", (username,)
        ).fetchone()
        if (
            user
            and user["is_active"]
            and _is_password_hash(user["password"])
            and check_password_hash(user["password"], password)
        ):
            login_attempts.pop(key, None)
            session.clear()
            session.permanent = True
            now = int(time.time())
            session.update(
                user_id=user["id"],
                created_at=now,
                last_seen=now,
                csrf_token=secrets.token_urlsafe(32),
            )
            audit("login_success", f"username={username}", actor_id=user["id"])
            db.commit()
            flash("로그인했습니다.")
            return redirect(url_for("dashboard"))

        audit("login_failure", f"username={username[:20]}", actor_id=None)
        db.commit()
        flash("아이디 또는 비밀번호가 올바르지 않습니다.")
        return redirect(url_for("login"))
    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    audit("logout")
    get_db().commit()
    session.clear()
    flash("로그아웃했습니다.")
    return redirect(url_for("index"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    db = get_db()
    if request.method == "POST":
        bio = request.form.get("bio", "").strip()
        if len(bio) > 500:
            flash("소개글은 500자 이하여야 합니다.")
            return redirect(url_for("profile"))
        db.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session["user_id"]))
        audit("profile_update")
        db.commit()
        flash("프로필을 업데이트했습니다.")
        return redirect(url_for("profile"))
    user = current_user()
    if user is None:
        session.clear()
        return redirect(url_for("login"))
    return render_template("profile.html", user=user)


@app.post("/profile/password")
@login_required
def change_password():
    db = get_db()
    current = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")

    row = db.execute(
        "SELECT password FROM user WHERE id = ?", (session["user_id"],)
    ).fetchone()
    # 민감 작업이므로 현재 비밀번호로 재인증한다.
    if row is None or not check_password_hash(row["password"], current):
        audit("password_change_denied")
        db.commit()
        flash("현재 비밀번호가 올바르지 않습니다.")
        return redirect(url_for("profile"))
    if not PASSWORD_MIN_LENGTH <= len(new_password) <= PASSWORD_MAX_LENGTH:
        flash(f"새 비밀번호는 {PASSWORD_MIN_LENGTH}~{PASSWORD_MAX_LENGTH}자여야 합니다.")
        return redirect(url_for("profile"))
    if new_password != confirm:
        flash("새 비밀번호가 일치하지 않습니다.")
        return redirect(url_for("profile"))
    if new_password == current:
        flash("이전과 다른 비밀번호를 사용해 주세요.")
        return redirect(url_for("profile"))

    db.execute(
        "UPDATE user SET password = ? WHERE id = ?",
        (generate_password_hash(new_password), session["user_id"]),
    )
    audit("password_change")
    db.commit()
    # 비밀번호 변경 후 세션을 재발급하여 탈취된 세션을 무효화한다.
    user_id = session["user_id"]
    session.clear()
    session.permanent = True
    now = int(time.time())
    session.update(
        user_id=user_id,
        created_at=now,
        last_seen=now,
        csrf_token=secrets.token_urlsafe(32),
    )
    flash("비밀번호를 변경했습니다.")
    return redirect(url_for("profile"))


@app.route("/user/<user_id>")
@login_required
def view_user(user_id):
    if not _valid_uuid(user_id):
        abort(404)
    db = get_db()
    # 비밀번호/잔액 등 민감 컬럼은 조회 대상에서 제외한다.
    user = db.execute(
        "SELECT id, username, bio, is_active FROM user WHERE id = ?", (user_id,)
    ).fetchone()
    if user is None:
        abort(404)
    products = db.execute(
        "SELECT id, title, price FROM product "
        "WHERE seller_id = ? AND status = 'active' ORDER BY rowid DESC",
        (user_id,),
    ).fetchall()
    return render_template("user.html", user=user, products=products)


# ---------------------------------------------------------------- 상품 관리

def _escape_like(value):
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _detect_image(data):
    """매직 바이트로 실제 이미지 형식을 판별한다.

    확장자나 Content-Type 은 클라이언트가 마음대로 정할 수 있으므로 신뢰하지 않는다.
    SVG 는 스크립트를 내장할 수 있어 화이트리스트에서 제외한다.
    """
    for signature, ext, mimetype in IMAGE_SIGNATURES:
        if data.startswith(signature):
            return ext, mimetype
    return None, None


def _save_product_image(storage):
    """업로드된 이미지를 검증 후 저장하고 서버가 생성한 파일명을 돌려준다.

    반환값: (파일명, 오류 메시지). 파일이 없으면 (None, None).
    """
    if storage is None or not storage.filename:
        return None, None

    data = storage.read(MAX_IMAGE_BYTES + 1)
    if len(data) > MAX_IMAGE_BYTES:
        return None, "이미지는 3MB 이하여야 합니다."
    if not data:
        return None, "빈 파일은 업로드할 수 없습니다."

    ext, _mimetype = _detect_image(data)
    if ext is None:
        return None, "JPG, PNG, GIF 이미지만 업로드할 수 있습니다."

    # 사용자가 보낸 파일명은 버리고 UUID 로 새로 만든다.
    # 경로 조작(../), 널 바이트, 이중 확장자(shell.php.jpg)가 모두 무력화된다.
    filename = f"{uuid.uuid4()}.{ext}"
    path = os.path.join(app.config["UPLOAD_DIR"], filename)
    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)
    return filename, None


def _delete_product_image(image_name):
    if not image_name or not IMAGE_NAME_RE.fullmatch(image_name):
        return
    try:
        os.remove(os.path.join(app.config["UPLOAD_DIR"], image_name))
    except OSError:
        pass


@app.route("/product/<product_id>/image")
def product_image(product_id):
    if not _valid_uuid(product_id):
        abort(404)
    product = get_db().execute(
        "SELECT image_name, status FROM product WHERE id = ?", (product_id,)
    ).fetchone()
    if product is None or not product["image_name"]:
        abort(404)
    # image_name 은 서버가 생성한 값이지만, DB 가 오염된 경우를 대비해 한 번 더 검증한다.
    if not IMAGE_NAME_RE.fullmatch(product["image_name"]):
        abort(404)
    ext = product["image_name"].rsplit(".", 1)[1]
    mimetype = {"jpg": "image/jpeg", "png": "image/png", "gif": "image/gif"}[ext]
    path = os.path.join(app.config["UPLOAD_DIR"], product["image_name"])
    if not os.path.isfile(path):
        abort(404)
    # 브라우저가 내용을 보고 타입을 추측하지 못하도록 mimetype 을 명시한다.
    # (전역 X-Content-Type-Options: nosniff 헤더와 함께 동작)
    return send_file(path, mimetype=mimetype, max_age=0)


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = current_user()
    if user is None:
        session.clear()
        return redirect(url_for("login"))

    query = request.args.get("q", "").strip()[:100]
    if query:
        # 검색어는 파라미터 바인딩 + LIKE 와일드카드 이스케이프로 처리한다.
        pattern = f"%{_escape_like(query)}%"
        products = db.execute(
            "SELECT * FROM product WHERE status IN ('active', 'reserved') "
            "AND (title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\') "
            "ORDER BY rowid DESC LIMIT 100",
            (pattern, pattern),
        ).fetchall()
    else:
        products = db.execute(
            "SELECT * FROM product WHERE status IN ('active', 'reserved') "
            "ORDER BY rowid DESC LIMIT 100"
        ).fetchall()
    return render_template("dashboard.html", products=products, user=user, query=query)


@app.route("/product/new", methods=["GET", "POST"])
@login_required
def new_product():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        price_text = request.form.get("price", "").strip()
        if not 1 <= len(title) <= 100 or not 1 <= len(description) <= 2000:
            flash("상품명은 1~100자, 설명은 1~2000자여야 합니다.")
            return redirect(url_for("new_product"))
        try:
            price = int(price_text)
        except ValueError:
            price = -1
        if not 0 <= price <= MAX_PRICE:
            flash("가격은 0~1,000,000,000 사이의 정수여야 합니다.")
            return redirect(url_for("new_product"))

        image_name, image_error = _save_product_image(request.files.get("image"))
        if image_error:
            flash(image_error)
            return redirect(url_for("new_product"))

        db = get_db()
        product_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO product (id, title, description, price, seller_id, status, "
            "image_name, created_at) VALUES (?, ?, ?, ?, ?, 'active', ?, datetime('now'))",
            (product_id, title, description, str(price), session["user_id"], image_name),
        )
        audit("product_create", f"product={product_id}")
        db.commit()
        flash("상품을 등록했습니다.")
        return redirect(url_for("dashboard"))
    return render_template("new_product.html")


@app.route("/product/<product_id>")
def view_product(product_id):
    if not _valid_uuid(product_id):
        abort(404)
    db = get_db()
    product = db.execute("SELECT * FROM product WHERE id = ?", (product_id,)).fetchone()
    if product is None:
        abort(404)
    viewer = current_user()
    is_admin = bool(viewer and viewer["is_admin"])
    # 차단된 상품은 소유자와 관리자에게만 보인다.
    # (예약중/판매완료 상품은 정상 상품이므로 누구나 볼 수 있다)
    if product["status"] == "blocked" and not (
        is_admin or (viewer and viewer["id"] == product["seller_id"])
    ):
        abort(404)
    seller = db.execute(
        "SELECT id, username FROM user WHERE id = ?", (product["seller_id"],)
    ).fetchone()
    my_trade = None
    if viewer is not None:
        my_trade = db.execute(
            "SELECT id, status, buyer_id FROM trade "
            "WHERE product_id = ? AND status IN (?, ?) ORDER BY rowid DESC",
            (product_id, *TRADE_OPEN_STATUSES),
        ).fetchone()
    return render_template(
        "view_product.html", product=product, seller=seller, trade=my_trade
    )


@app.route("/my/products")
@login_required
def my_products():
    products = get_db().execute(
        "SELECT * FROM product WHERE seller_id = ? ORDER BY rowid DESC",
        (session["user_id"],),
    ).fetchall()
    return render_template("my_products.html", products=products)


def _owned_product_or_404(product_id):
    if not _valid_uuid(product_id):
        abort(404)
    product = get_db().execute(
        "SELECT * FROM product WHERE id = ?", (product_id,)
    ).fetchone()
    if product is None:
        abort(404)
    # IDOR 방지: 소유자가 아니면 존재 여부조차 알리지 않는다.
    if product["seller_id"] != session.get("user_id"):
        audit("product_idor_attempt", f"product={product_id}")
        get_db().commit()
        abort(404)
    return product


@app.route("/product/<product_id>/edit", methods=["GET", "POST"])
@login_required
def edit_product(product_id):
    product = _owned_product_or_404(product_id)
    # 거래가 진행 중인 상품은 수정할 수 없다.
    # (예약 후 판매자가 가격이나 설명을 바꾸는 것을 막는다)
    if product["status"] != "active":
        flash("거래 중이거나 차단된 상품은 수정할 수 없습니다.")
        return redirect(url_for("my_products"))
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        price_text = request.form.get("price", "").strip()
        if not 1 <= len(title) <= 100 or not 1 <= len(description) <= 2000:
            flash("상품명은 1~100자, 설명은 1~2000자여야 합니다.")
            return redirect(url_for("edit_product", product_id=product_id))
        try:
            price = int(price_text)
        except ValueError:
            price = -1
        if not 0 <= price <= MAX_PRICE:
            flash("가격은 0~1,000,000,000 사이의 정수여야 합니다.")
            return redirect(url_for("edit_product", product_id=product_id))

        image_name, image_error = _save_product_image(request.files.get("image"))
        if image_error:
            flash(image_error)
            return redirect(url_for("edit_product", product_id=product_id))

        db = get_db()
        if image_name:
            db.execute(
                "UPDATE product SET title = ?, description = ?, price = ?, image_name = ? "
                "WHERE id = ? AND seller_id = ?",
                (title, description, str(price), image_name, product_id, session["user_id"]),
            )
            _delete_product_image(product["image_name"])
        else:
            db.execute(
                "UPDATE product SET title = ?, description = ?, price = ? "
                "WHERE id = ? AND seller_id = ?",
                (title, description, str(price), product_id, session["user_id"]),
            )
        audit("product_update", f"product={product_id}")
        db.commit()
        flash("상품을 수정했습니다.")
        return redirect(url_for("my_products"))
    return render_template("edit_product.html", product=product)


@app.post("/product/<product_id>/delete")
@login_required
def delete_product(product_id):
    product = _owned_product_or_404(product_id)
    db = get_db()
    # 진행 중인 거래가 있으면 삭제를 막는다.
    # 삭제를 허용하면 구매자의 에스크로 대금이 갈 곳을 잃는다.
    open_trade = db.execute(
        "SELECT 1 FROM trade WHERE product_id = ? AND status IN (?, ?)",
        (product_id, *TRADE_OPEN_STATUSES),
    ).fetchone()
    if open_trade:
        flash("진행 중인 거래가 있어 삭제할 수 없습니다.")
        return redirect(url_for("my_products"))

    db.execute(
        "DELETE FROM product WHERE id = ? AND seller_id = ?",
        (product_id, session["user_id"]),
    )
    audit("product_delete", f"product={product_id}")
    db.commit()
    _delete_product_image(product["image_name"])
    flash("상품을 삭제했습니다.")
    return redirect(url_for("my_products"))


# ---------------------------------------------------------------- 송금

@app.route("/wallet", methods=["GET", "POST"])
@login_required
def wallet():
    db = get_db()
    if request.method == "POST":
        if _rate_limited(
            transfer_attempts,
            session["user_id"],
            TRANSFER_MAX_ATTEMPTS,
            TRANSFER_WINDOW_SECONDS,
        ):
            abort(429)

        receiver_name = request.form.get("receiver", "").strip()
        amount_text = request.form.get("amount", "").strip()
        try:
            amount = int(amount_text)
        except ValueError:
            amount = 0
        # 음수/0 송금으로 잔액을 늘리는 공격을 차단한다.
        if not 1 <= amount <= MAX_TRANSFER:
            flash("송금액은 1 이상의 정수여야 합니다.")
            return redirect(url_for("wallet"))

        receiver = db.execute(
            "SELECT id, is_active FROM user WHERE username = ?", (receiver_name,)
        ).fetchone()
        if receiver is None or not receiver["is_active"]:
            flash("송금할 수 없는 상대입니다.")
            return redirect(url_for("wallet"))
        if receiver["id"] == session["user_id"]:
            flash("자기 자신에게는 송금할 수 없습니다.")
            return redirect(url_for("wallet"))

        try:
            # 단일 트랜잭션 + 조건부 UPDATE 로 경쟁 상태(이중 지출)를 막는다.
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute(
                "UPDATE user SET balance = balance - ? WHERE id = ? AND balance >= ?",
                (amount, session["user_id"], amount),
            )
            if cursor.rowcount != 1:
                db.rollback()
                flash("잔액이 부족합니다.")
                return redirect(url_for("wallet"))
            db.execute(
                "UPDATE user SET balance = balance + ? WHERE id = ?",
                (amount, receiver["id"]),
            )
            db.execute(
                "INSERT INTO transfer (id, sender_id, receiver_id, amount, created_at) "
                "VALUES (?, ?, ?, ?, datetime('now'))",
                (str(uuid.uuid4()), session["user_id"], receiver["id"], amount),
            )
            db.execute(
                "INSERT INTO audit_log (id, actor_id, action, detail, ip, created_at) "
                "VALUES (?, ?, 'transfer', ?, ?, datetime('now'))",
                (
                    str(uuid.uuid4()),
                    session["user_id"],
                    f"to={receiver['id']} amount={amount}",
                    request.remote_addr,
                ),
            )
            db.commit()
        except sqlite3.Error:
            db.rollback()
            flash("송금 처리 중 오류가 발생했습니다.")
            return redirect(url_for("wallet"))

        flash(f"{amount}원을 송금했습니다.")
        return redirect(url_for("wallet"))

    user = current_user()
    history = db.execute(
        "SELECT t.amount, t.created_at, t.sender_id, t.receiver_id, "
        "  s.username AS sender_name, r.username AS receiver_name "
        "FROM transfer t "
        "JOIN user s ON s.id = t.sender_id "
        "JOIN user r ON r.id = t.receiver_id "
        "WHERE t.sender_id = ? OR t.receiver_id = ? "
        "ORDER BY t.rowid DESC LIMIT 50",
        (session["user_id"], session["user_id"]),
    ).fetchall()
    return render_template("wallet.html", user=user, history=history)


# ---------------------------------------------------------------- 거래 (에스크로)

TRADE_LABELS = {
    "requested": "구매 요청",
    "accepted": "거래 진행중",
    "completed": "거래 완료",
    "cancelled": "취소됨",
}


@app.post("/product/<product_id>/buy")
@login_required
def buy_product(product_id):
    if not _valid_uuid(product_id):
        abort(404)
    db = get_db()
    product = db.execute("SELECT * FROM product WHERE id = ?", (product_id,)).fetchone()
    if product is None:
        abort(404)
    if product["seller_id"] == session["user_id"]:
        flash("자신의 상품은 구매할 수 없습니다.")
        return redirect(url_for("view_product", product_id=product_id))
    if product["status"] != "active":
        flash("현재 구매할 수 없는 상품입니다.")
        return redirect(url_for("view_product", product_id=product_id))

    seller = db.execute(
        "SELECT id, is_active FROM user WHERE id = ?", (product["seller_id"],)
    ).fetchone()
    if seller is None or not seller["is_active"]:
        flash("현재 구매할 수 없는 상품입니다.")
        return redirect(url_for("view_product", product_id=product_id))

    try:
        amount = int(product["price"])
    except (TypeError, ValueError):
        flash("현재 구매할 수 없는 상품입니다.")
        return redirect(url_for("view_product", product_id=product_id))

    try:
        db.execute("BEGIN IMMEDIATE")
        # 상품을 원자적으로 선점한다. 동시에 두 명이 구매를 눌러도
        # status='active' 조건을 만족하는 UPDATE 는 하나만 성공한다.
        cursor = db.execute(
            "UPDATE product SET status = 'reserved' WHERE id = ? AND status = 'active'",
            (product_id,),
        )
        if cursor.rowcount != 1:
            db.rollback()
            flash("이미 다른 사용자가 거래를 시작한 상품입니다.")
            return redirect(url_for("view_product", product_id=product_id))

        # 구매 대금을 즉시 차감해 에스크로로 보관한다.
        # 판매자에게는 구매 확정 시점에만 지급된다.
        cursor = db.execute(
            "UPDATE user SET balance = balance - ? WHERE id = ? AND balance >= ?",
            (amount, session["user_id"], amount),
        )
        if cursor.rowcount != 1:
            db.rollback()
            flash("잔액이 부족합니다.")
            return redirect(url_for("view_product", product_id=product_id))

        trade_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO trade (id, product_id, buyer_id, seller_id, amount, status, "
            "created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 'requested', datetime('now'), datetime('now'))",
            (trade_id, product_id, session["user_id"], product["seller_id"], amount),
        )
        audit("trade_request", f"trade={trade_id} product={product_id} amount={amount}")
        db.commit()
    except sqlite3.Error:
        db.rollback()
        flash("거래 처리 중 오류가 발생했습니다.")
        return redirect(url_for("view_product", product_id=product_id))

    flash("구매를 요청했습니다. 판매자가 수락하면 거래가 시작됩니다.")
    return redirect(url_for("trades"))


@app.route("/trades")
@login_required
def trades():
    rows = get_db().execute(
        "SELECT t.*, p.title AS product_title, "
        "  b.username AS buyer_name, s.username AS seller_name "
        "FROM trade t "
        "LEFT JOIN product p ON p.id = t.product_id "
        "JOIN user b ON b.id = t.buyer_id "
        "JOIN user s ON s.id = t.seller_id "
        "WHERE t.buyer_id = ? OR t.seller_id = ? "
        "ORDER BY t.rowid DESC LIMIT 100",
        (session["user_id"], session["user_id"]),
    ).fetchall()
    return render_template("trades.html", trades=rows, labels=TRADE_LABELS)


@app.post("/trade/<trade_id>/accept")
@login_required
def accept_trade(trade_id):
    if not _valid_uuid(trade_id):
        abort(404)
    db = get_db()
    # 권한(판매자 본인)과 상태 전이를 하나의 조건부 UPDATE 로 검사한다.
    # 재전송이나 동시 클릭이 있어도 두 번 반영되지 않는다.
    cursor = db.execute(
        "UPDATE trade SET status = 'accepted', updated_at = datetime('now') "
        "WHERE id = ? AND seller_id = ? AND status = 'requested'",
        (trade_id, session["user_id"]),
    )
    if cursor.rowcount != 1:
        db.rollback()
        audit("trade_accept_denied", f"trade={trade_id}")
        db.commit()
        abort(404)
    audit("trade_accept", f"trade={trade_id}")
    db.commit()
    flash("구매 요청을 수락했습니다.")
    return redirect(url_for("trades"))


@app.post("/trade/<trade_id>/complete")
@login_required
def complete_trade(trade_id):
    if not _valid_uuid(trade_id):
        abort(404)
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        trade = db.execute(
            "SELECT * FROM trade WHERE id = ?", (trade_id,)
        ).fetchone()
        # 구매 확정은 구매자만 할 수 있다.
        # 판매자가 스스로 정산을 트리거하면 물건 없이 대금을 챙길 수 있다.
        cursor = db.execute(
            "UPDATE trade SET status = 'completed', updated_at = datetime('now') "
            "WHERE id = ? AND buyer_id = ? AND status = 'accepted'",
            (trade_id, session["user_id"]),
        )
        if cursor.rowcount != 1:
            db.rollback()
            audit("trade_complete_denied", f"trade={trade_id}")
            db.commit()
            abort(404)

        # 에스크로에 보관하던 대금을 판매자에게 지급한다.
        db.execute(
            "UPDATE user SET balance = balance + ? WHERE id = ?",
            (trade["amount"], trade["seller_id"]),
        )
        db.execute(
            "INSERT INTO transfer (id, sender_id, receiver_id, amount, created_at) "
            "VALUES (?, ?, ?, ?, datetime('now'))",
            (str(uuid.uuid4()), trade["buyer_id"], trade["seller_id"], trade["amount"]),
        )
        db.execute("UPDATE product SET status = 'sold' WHERE id = ?", (trade["product_id"],))
        db.execute(
            "INSERT INTO audit_log (id, actor_id, action, detail, ip, created_at) "
            "VALUES (?, ?, 'trade_complete', ?, ?, datetime('now'))",
            (
                str(uuid.uuid4()),
                session["user_id"],
                f"trade={trade_id} amount={trade['amount']}",
                request.remote_addr,
            ),
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        flash("거래 처리 중 오류가 발생했습니다.")
        return redirect(url_for("trades"))

    flash("구매를 확정했습니다. 판매자에게 대금이 전달되었습니다.")
    return redirect(url_for("trades"))


@app.post("/trade/<trade_id>/cancel")
@login_required
def cancel_trade(trade_id):
    if not _valid_uuid(trade_id):
        abort(404)
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        trade = db.execute("SELECT * FROM trade WHERE id = ?", (trade_id,)).fetchone()
        # 구매자와 판매자 모두 취소할 수 있다. 대금은 에스크로에 있으므로 환불이 안전하다.
        cursor = db.execute(
            "UPDATE trade SET status = 'cancelled', updated_at = datetime('now') "
            "WHERE id = ? AND (buyer_id = ? OR seller_id = ?) "
            "AND status IN ('requested', 'accepted')",
            (trade_id, session["user_id"], session["user_id"]),
        )
        if cursor.rowcount != 1:
            db.rollback()
            audit("trade_cancel_denied", f"trade={trade_id}")
            db.commit()
            abort(404)

        # 에스크로 대금을 구매자에게 환불하고 상품을 다시 판매중으로 되돌린다.
        db.execute(
            "UPDATE user SET balance = balance + ? WHERE id = ?",
            (trade["amount"], trade["buyer_id"]),
        )
        db.execute(
            "UPDATE product SET status = 'active' WHERE id = ? AND status = 'reserved'",
            (trade["product_id"],),
        )
        db.execute(
            "INSERT INTO audit_log (id, actor_id, action, detail, ip, created_at) "
            "VALUES (?, ?, 'trade_cancel', ?, ?, datetime('now'))",
            (
                str(uuid.uuid4()),
                session["user_id"],
                f"trade={trade_id} refund={trade['amount']}",
                request.remote_addr,
            ),
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        flash("거래 처리 중 오류가 발생했습니다.")
        return redirect(url_for("trades"))

    flash("거래를 취소했습니다. 대금은 환불되었습니다.")
    return redirect(url_for("trades"))


# ---------------------------------------------------------------- 신고 / 차단

def _apply_report_thresholds(db, target_id, target_type):
    """서로 다른 신고자 수가 임계값을 넘으면 자동으로 차단/휴면 처리한다."""
    distinct = db.execute(
        "SELECT COUNT(DISTINCT reporter_id) AS c FROM report WHERE target_id = ?",
        (target_id,),
    ).fetchone()["c"]
    if target_type == "product" and distinct >= PRODUCT_BLOCK_THRESHOLD:
        # 거래가 진행 중인(reserved) 상품은 건드리지 않는다.
        # 차단해 버리면 구매자의 에스크로 대금이 묶인 채 방치된다.
        db.execute(
            "UPDATE product SET status = 'blocked' WHERE id = ? AND status = 'active'",
            (target_id,),
        )
        audit("product_auto_blocked", f"product={target_id} reports={distinct}")
    elif target_type == "user" and distinct >= USER_SUSPEND_THRESHOLD:
        db.execute("UPDATE user SET is_active = 0 WHERE id = ?", (target_id,))
        audit("user_auto_suspended", f"user={target_id} reports={distinct}")


@app.route("/report", methods=["GET", "POST"])
@login_required
def report():
    if request.method == "POST":
        if _rate_limited(
            report_attempts,
            session["user_id"],
            REPORT_MAX_ATTEMPTS,
            REPORT_WINDOW_SECONDS,
        ):
            abort(429)

        target_id = request.form.get("target_id", "").strip()
        reason = request.form.get("reason", "").strip()
        if not _valid_uuid(target_id):
            flash("신고 대상 ID 형식이 올바르지 않습니다.")
            return redirect(url_for("report"))
        if not 10 <= len(reason) <= 1000:
            flash("신고 사유는 10~1000자여야 합니다.")
            return redirect(url_for("report"))

        db = get_db()
        target_type = None
        if db.execute("SELECT 1 FROM user WHERE id = ?", (target_id,)).fetchone():
            target_type = "user"
        elif db.execute("SELECT 1 FROM product WHERE id = ?", (target_id,)).fetchone():
            target_type = "product"
        if target_type is None or target_id == session["user_id"]:
            flash("신고할 수 없는 대상입니다.")
            return redirect(url_for("report"))

        try:
            db.execute(
                "INSERT INTO report (id, reporter_id, target_id, target_type, reason, created_at) "
                "VALUES (?, ?, ?, ?, ?, datetime('now'))",
                (str(uuid.uuid4()), session["user_id"], target_id, target_type, reason),
            )
        except sqlite3.IntegrityError:
            # UNIQUE(reporter_id, target_id) 위반 = 동일 대상 중복 신고
            flash("이미 신고한 대상입니다.")
            return redirect(url_for("report"))

        audit("report_create", f"target={target_id} type={target_type}")
        _apply_report_thresholds(db, target_id, target_type)
        db.commit()
        flash("신고를 접수했습니다.")
        return redirect(url_for("dashboard"))
    return render_template("report.html")


# ---------------------------------------------------------------- 관리자

@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    users = db.execute(
        "SELECT id, username, balance, is_admin, is_active, created_at "
        "FROM user ORDER BY rowid DESC LIMIT 200"
    ).fetchall()
    products = db.execute(
        "SELECT p.id, p.title, p.price, p.status, u.username AS seller "
        "FROM product p LEFT JOIN user u ON u.id = p.seller_id "
        "ORDER BY p.rowid DESC LIMIT 200"
    ).fetchall()
    reports = db.execute(
        "SELECT r.id, r.target_id, r.target_type, r.reason, r.created_at, "
        "  u.username AS reporter "
        "FROM report r LEFT JOIN user u ON u.id = r.reporter_id "
        "ORDER BY r.rowid DESC LIMIT 200"
    ).fetchall()
    logs = db.execute(
        "SELECT action, detail, ip, created_at FROM audit_log "
        "ORDER BY rowid DESC LIMIT 100"
    ).fetchall()
    return render_template(
        "admin.html", users=users, products=products, reports=reports, logs=logs
    )


@app.post("/admin/user/<user_id>/toggle")
@admin_required
def admin_toggle_user(user_id):
    if not _valid_uuid(user_id):
        abort(404)
    db = get_db()
    target = db.execute(
        "SELECT id, is_active, is_admin FROM user WHERE id = ?", (user_id,)
    ).fetchone()
    if target is None:
        abort(404)
    if target["id"] == session["user_id"]:
        flash("자기 자신의 계정 상태는 변경할 수 없습니다.")
        return redirect(url_for("admin_dashboard"))
    if target["is_admin"]:
        flash("다른 관리자 계정은 변경할 수 없습니다.")
        return redirect(url_for("admin_dashboard"))

    new_state = 0 if target["is_active"] else 1
    db.execute("UPDATE user SET is_active = ? WHERE id = ?", (new_state, user_id))
    audit("admin_toggle_user", f"user={user_id} is_active={new_state}")
    db.commit()
    flash("계정 상태를 변경했습니다.")
    return redirect(url_for("admin_dashboard"))


@app.post("/admin/product/<product_id>/toggle")
@admin_required
def admin_toggle_product(product_id):
    if not _valid_uuid(product_id):
        abort(404)
    db = get_db()
    product = db.execute(
        "SELECT id, status FROM product WHERE id = ?", (product_id,)
    ).fetchone()
    if product is None:
        abort(404)
    new_status = "blocked" if product["status"] == "active" else "active"
    db.execute("UPDATE product SET status = ? WHERE id = ?", (new_status, product_id))
    audit("admin_toggle_product", f"product={product_id} status={new_status}")
    db.commit()
    flash("상품 상태를 변경했습니다.")
    return redirect(url_for("admin_dashboard"))


@app.post("/admin/product/<product_id>/delete")
@admin_required
def admin_delete_product(product_id):
    if not _valid_uuid(product_id):
        abort(404)
    db = get_db()
    if db.execute("SELECT 1 FROM product WHERE id = ?", (product_id,)).fetchone() is None:
        abort(404)
    db.execute("DELETE FROM product WHERE id = ?", (product_id,))
    audit("admin_delete_product", f"product={product_id}")
    db.commit()
    flash("상품을 삭제했습니다.")
    return redirect(url_for("admin_dashboard"))


# ---------------------------------------------------------------- 1:1 채팅

@app.route("/chat")
@login_required
def chat_list():
    db = get_db()
    partners = db.execute(
        "SELECT u.id, u.username, MAX(m.rowid) AS last_row FROM message m "
        "JOIN user u ON u.id = CASE WHEN m.sender_id = ? THEN m.receiver_id "
        "                            ELSE m.sender_id END "
        "WHERE m.sender_id = ? OR m.receiver_id = ? "
        "GROUP BY u.id, u.username ORDER BY last_row DESC LIMIT 50",
        (session["user_id"], session["user_id"], session["user_id"]),
    ).fetchall()
    return render_template("chat_list.html", partners=partners)


@app.route("/chat/<user_id>")
@login_required
def chat_with(user_id):
    if not _valid_uuid(user_id) or user_id == session["user_id"]:
        abort(404)
    db = get_db()
    partner = db.execute(
        "SELECT id, username FROM user WHERE id = ? AND is_active = 1", (user_id,)
    ).fetchone()
    if partner is None:
        abort(404)
    # 대화 상대가 나 자신인 메시지만 조회 (다른 사람의 대화 열람 차단).
    messages = db.execute(
        "SELECT m.content, m.created_at, m.sender_id, u.username AS sender_name "
        "FROM message m JOIN user u ON u.id = m.sender_id "
        "WHERE (m.sender_id = ? AND m.receiver_id = ?) "
        "   OR (m.sender_id = ? AND m.receiver_id = ?) "
        "ORDER BY m.rowid ASC LIMIT 200",
        (session["user_id"], user_id, user_id, session["user_id"]),
    ).fetchall()
    return render_template("chat.html", partner=partner, messages=messages)


# ---------------------------------------------------------------- SocketIO

@socketio.on("connect")
def handle_connect():
    user_id = session.get("user_id")
    if not user_id:
        return False
    row = get_db().execute(
        "SELECT is_active FROM user WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None or not row["is_active"]:
        return False
    # 1:1 메시지 전달을 위해 사용자 전용 룸에 참여시킨다.
    join_room(user_id)


def _authenticated_socket_user():
    user_id = session.get("user_id")
    if not user_id:
        disconnect()
        return None
    user = get_db().execute(
        "SELECT id, username, is_active FROM user WHERE id = ?", (user_id,)
    ).fetchone()
    if user is None or not user["is_active"]:
        disconnect()
        return None
    return user


def _clean_message(data):
    if not isinstance(data, dict):
        return None
    message = data.get("message")
    if not isinstance(message, str):
        return None
    message = message.strip()
    if not 1 <= len(message) <= MAX_CHAT_LENGTH:
        return None
    return message


@socketio.on("send_message")
def handle_send_message_event(data):
    user = _authenticated_socket_user()
    if user is None:
        return
    if _rate_limited(chat_attempts, user["id"], CHAT_MAX_MESSAGES, CHAT_WINDOW_SECONDS):
        return
    message = _clean_message(data)
    if message is None:
        return
    # username 은 클라이언트 입력이 아닌 서버 세션에서 가져온다(신원 위조 방지).
    send(
        {
            "message_id": str(uuid.uuid4()),
            "username": user["username"],
            "message": message,
        },
        broadcast=True,
    )


@socketio.on("private_message")
def handle_private_message(data):
    user = _authenticated_socket_user()
    if user is None:
        return
    if _rate_limited(chat_attempts, user["id"], CHAT_MAX_MESSAGES, CHAT_WINDOW_SECONDS):
        return
    message = _clean_message(data)
    if message is None:
        return
    receiver_id = data.get("to")
    if not _valid_uuid(receiver_id) or receiver_id == user["id"]:
        return

    db = get_db()
    receiver = db.execute(
        "SELECT id FROM user WHERE id = ? AND is_active = 1", (receiver_id,)
    ).fetchone()
    if receiver is None:
        return
    db.execute(
        "INSERT INTO message (id, sender_id, receiver_id, content, created_at) "
        "VALUES (?, ?, ?, ?, datetime('now'))",
        (str(uuid.uuid4()), user["id"], receiver_id, message),
    )
    db.commit()

    payload = {
        "message_id": str(uuid.uuid4()),
        "from": user["id"],
        "username": user["username"],
        "message": message,
    }
    # 발신자와 수신자의 룸에만 전달한다(브로드캐스트 금지).
    emit("private_message", payload, to=receiver_id)
    emit("private_message", payload, to=user["id"])


if __name__ == "__main__":
    init_db()
    socketio.run(app, debug=False)

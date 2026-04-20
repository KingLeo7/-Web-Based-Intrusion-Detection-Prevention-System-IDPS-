from flask import Flask, request, jsonify, send_from_directory
import re
import sqlite3

app = Flask(__name__)

# ---------- DATABASE SETUP ----------
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Simple in-memory storage
logs = [
    {"url": "/login?id=1 OR 1=1", "result": "SQL Injection", "safe": False},
    {"url": "<script>alert(1)</script>", "result": "XSS Attack", "safe": False},
    {"url": "/home", "result": "Safe", "safe": True},
]

blocked_ips = ["192.168.1.10", "192.168.1.15"]

stats = {"requests": 120, "attacks": 10, "blocked": 3}

# users = []  # Simple in-memory user storage - removed, using database now


def check_sql(url):
    patterns = [
        r"(or|and)\s+\d+=\d+", 
        r"(union|select|insert|drop|delete|update|alter|create|exec|execute|--|#|/\*|\*/)", 
        r"'.*'", 
        r'".*"',
        r"1=1", 
        r"admin'--", 
        r"' or '1'='1", 
        r"'; drop table", 
        r"xp_cmdshell", 
        r"script>",
        r"<script"
    ]
    for p in patterns:
        if re.search(p, url, re.IGNORECASE):
            return "SQL Injection"
    return None


def check_xss(url):
    patterns = [
        r"<script", 
        r"javascript:", 
        r"onerror=", 
        r"onload=", 
        r"onmouseover=", 
        r"onclick=", 
        r"<img", 
        r"<iframe", 
        r"<object", 
        r"<embed", 
        r"alert\(", 
        r"confirm\(", 
        r"prompt\(", 
        r"eval\(", 
        r"document\.cookie", 
        r"document\.location", 
        r"window\.location", 
        r"innerHTML", 
        r"outerHTML"
    ]
    for p in patterns:
        if re.search(p, url, re.IGNORECASE):
            return "XSS Attack"
    return None


def check_brute(url):
    patterns = [
        r"(login|admin|passwd|password|auth|signin|logon)",
        r"(retry|attempt|failed|error)",
        r"(brute|force|attack)",
        r"(multiple|repeated)",
        r"(lockout|blocked)",
        r"(captcha|bypass)"
    ]
    count = sum(1 for p in patterns if re.search(p, url, re.IGNORECASE))
    if count >= 2:
        return "Brute Force"
    return None


def check_csrf(url):
    patterns = [r"csrf", r"token", r"cross.site.request.forgery", r"referer", r"origin"]
    for p in patterns:
        if re.search(p, url, re.IGNORECASE):
            return "CSRF Attack"
    return None


def check_rfi(url):
    patterns = [r"http://", r"https://", r"ftp://", r"file://", r"php://", r"data://", r"include", r"require", r"remote.file.inclusion"]
    for p in patterns:
        if re.search(p, url, re.IGNORECASE):
            return "Remote File Inclusion"
    return None


def check_lfi(url):
    patterns = [r"\.\./", r"\.\.\\", r"etc/passwd", r"boot.ini", r"local.file.inclusion", r"directory.traversal"]
    for p in patterns:
        if re.search(p, url, re.IGNORECASE):
            return "Local File Inclusion"
    return None


@app.route("/")
def index():
    return send_from_directory(".", "login.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.json
    url = data.get("url", "")
    check_type = data.get("type", "full")

    result = None

    if check_type == "sql":
        result = check_sql(url)
    elif check_type == "xss":
        result = check_xss(url)
    elif check_type == "brute":
        result = check_brute(url)
    elif check_type == "csrf":
        result = check_csrf(url)
    elif check_type == "rfi":
        result = check_rfi(url)
    elif check_type == "lfi":
        result = check_lfi(url)
    else:  # full scan
        result = check_sql(url) or check_xss(url) or check_brute(url) or check_csrf(url) or check_rfi(url) or check_lfi(url)

    if not result:
        result = "Safe"

    safe = result == "Safe"

    # Update stats
    stats["requests"] += 1
    if not safe:
        stats["attacks"] += 1
        ip = request.remote_addr or "unknown"
        if ip not in blocked_ips:
            blocked_ips.append(ip)
            stats["blocked"] += 1

    # Add to logs
    logs.insert(0, {"url": url, "result": result, "safe": safe})
    if len(logs) > 20:
        logs.pop()

    return jsonify({"result": result, "safe": safe})


@app.route("/api/data")
def get_data():
    return jsonify({
        "stats": stats,
        "logs": logs[:8],
        "blocked_ips": blocked_ips[-5:]
    })


@app.route("/api/clear-logs", methods=["POST"])
def clear_logs():
    global logs
    logs = []
    return jsonify({"success": True})


@app.route("/api/clear-blocked", methods=["POST"])
def clear_blocked():
    global blocked_ips
    blocked_ips = []
    return jsonify({"success": True})


@app.route("/api/reset-stats", methods=["POST"])
def reset_stats():
    global stats
    stats = {"requests": 0, "attacks": 0, "blocked": 0}
    return jsonify({"success": True})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        
        if user:
            return send_from_directory(".", "index.html")  # redirect to dashboard
        else:
            return "Invalid credentials"
    return send_from_directory(".", "login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already exists"
        finally:
            conn.close()
        
        return send_from_directory(".", "login.html")  # redirect to login
    return send_from_directory(".", "register.html")


if __name__ == "__main__":
    app.run(debug=True, port=5000)

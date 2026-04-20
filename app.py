from flask import Flask, render_template, request, redirect
import sqlite3

app = Flask(__name__)

# ---------- DATABASE SETUP ----------
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')

    # Logs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data TEXT,
            result TEXT
        )
    ''')

    conn.commit()
    conn.close()

init_db()

# ---------- DETECTION FUNCTION ----------
def detect_attack(data):
    data = data.lower()

    if "or 1=1" in data or "'" in data or "--" in data:
        return "SQL Injection Detected"
    elif "<script>" in data:
        return "XSS Attack Detected"
    else:
        return "Safe Request"

# ---------- ROUTES ----------

# Login page
@app.route('/')
def login_page():
    return render_template('login.html')

# Login check
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    user = c.fetchone()
    conn.close()

    if user:
        return render_template('dashboard.html')
    else:
        return "Invalid Username or Password ❌"

# Register page + save
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()

        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
        except:
            return "Username already exists ❌"

        conn.close()
        return redirect('/')

    return render_template('register.html')

# Analyze input
@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.form['data']
    result = detect_attack(data)

    # Save log
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("INSERT INTO logs (data, result) VALUES (?, ?)", (data, result))
    conn.commit()
    conn.close()

    return render_template('dashboard.html', result=result, data=data)

# ---------- RUN ----------
if __name__ == '__main__':
    app.run(debug=True)
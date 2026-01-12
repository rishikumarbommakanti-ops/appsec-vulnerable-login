from flask import Flask, request, session, redirect, url_for
import sqlite3
import os
import bcrypt
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secure random secret

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS login_attempts (username TEXT, attempts INTEGER, last_attempt TIMESTAMP, PRIMARY KEY (username))''')
    # Secure: hashed password
    hashed = bcrypt.hashpw(b'password', bcrypt.gensalt())
    c.execute("INSERT OR IGNORE INTO users VALUES ('admin', ?)", (hashed,))
    conn.commit()
    conn.close()

def reset_attempts(username):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("DELETE FROM login_attempts WHERE username=?", (username,))
    conn.commit()
    conn.close()

def check_attempts(username):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT attempts, last_attempt FROM login_attempts WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        attempts, last = row
        if datetime.now() - datetime.fromisoformat(last) > timedelta(minutes=15):
            reset_attempts(username)
            return 0
        if attempts >= 5:
            return attempts
    return 0

def increment_attempt(username):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute("INSERT OR REPLACE INTO login_attempts VALUES (?, 1, ?) ON CONFLICT(username) DO UPDATE SET attempts=attempts+1, last_attempt=?", (username, now, now))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return '''
    <h1>Secure Login Demo</h1>
    <a href="/signup">Signup</a> | <a href="/login">Login</a>
    '''

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            # Secure: Parameterized query
            c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
            conn.commit()
            return 'Signup successful! <a href="/login">Login</a>'
        except sqlite3.IntegrityError:
            return 'Username exists. <a href="/login">Login</a>'
        finally:
            conn.close()
    return '''
    <form method="post">
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit" value="Signup">
    </form>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        attempts = check_attempts(username)
        if attempts >= 5:
            return 'Too many failed attempts. Try again later. <a href="/login">Retry</a>'
        password = request.form['password'].encode('utf-8')
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        # Secure: Parameterized query
        c.execute("SELECT password_hash FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        if row:
            if bcrypt.checkpw(password, row[0]):
                reset_attempts(username)
                # Secure session: only username, no password
                session['user'] = username
                return f'Welcome, {username}! <a href="/dashboard">Dashboard</a>'
        increment_attempt(username)
        return 'Invalid credentials. <a href="/login">Try again</a>'
    return '''
    <form method="post">
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return f'Secure Dashboard for {session["user"]}'
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

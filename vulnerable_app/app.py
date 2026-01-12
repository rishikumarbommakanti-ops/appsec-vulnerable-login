from flask import Flask, request, session, redirect, url_for
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'supersecret'  # Insecure: hard-coded weak secret

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)''')
    c.execute("INSERT OR IGNORE INTO users VALUES ('admin', 'password')")
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return '''
    <h1>Vulnerable Login Demo</h1>
    <a href="/signup">Signup</a> | <a href="/login">Login</a>
    '''

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        # Vulnerable: Plaintext storage
        c.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')")
        conn.commit()
        conn.close()
        return 'Signup successful! <a href="/login">Login</a>'
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
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        # Vulnerable: SQL Injection via f-string
        c.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")
        user = c.fetchone()
        conn.close()
        if user:
            # Insecure session: stores sensitive data plainly
            session['user'] = username
            session['password'] = password  # Never do this!
            return f'Welcome, {username}! <a href="/dashboard">Dashboard</a>'
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
        return f'Dashboard for {session["user"]}'
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

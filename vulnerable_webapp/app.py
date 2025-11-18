#!/usr/bin/env python3
"""
Vulnerable Web Application - FOR EDUCATIONAL PURPOSES ONLY
This application contains INTENTIONAL security vulnerabilities
DO NOT deploy this in production or on public networks
"""

from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'insecure_secret_key_12345'  # Intentionally weak secret

# Initialize database
def init_db():
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, 
                  email TEXT, role TEXT, balance INTEGER)''')
    
    # Create messages table
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY, user_id INTEGER, 
                  message TEXT, timestamp TEXT)''')
    
    # Insert default users (weak passwords)
    users = [
        ('admin', 'admin123', 'admin@cyberlab.com', 'admin', 10000),
        ('john', 'password', 'john@example.com', 'user', 5000),
        ('alice', '123456', 'alice@example.com', 'user', 3000),
        ('bob', 'qwerty', 'bob@example.com', 'user', 2000)
    ]
    
    for user in users:
        c.execute("SELECT * FROM users WHERE username=?", (user[0],))
        if not c.fetchone():
            c.execute("INSERT INTO users (username, password, email, role, balance) VALUES (?,?,?,?,?)", 
                     user)
    
    conn.commit()
    conn.close()

# Home page
@app.route('/')
def index():
    return render_template('index.html')

# VULNERABILITY 1: SQL Injection
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # VULNERABLE: Direct string concatenation - SQL Injection
        conn = sqlite3.connect('vulnerable.db')
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        
        try:
            c.execute(query)
            user = c.fetchone()
            conn.close()
            
            if user:
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[4]
                return redirect(url_for('dashboard'))
            else:
                return render_template('login.html', error='Invalid credentials')
        except Exception as e:
            return render_template('login.html', error=f'Database error: {str(e)}')
    
    return render_template('login.html')

# VULNERABILITY 2: XSS (Cross-Site Scripting)
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (session['user_id'],))
    user = c.fetchone()
    
    c.execute("SELECT * FROM messages WHERE user_id=? ORDER BY timestamp DESC", (session['user_id'],))
    messages = c.fetchall()
    conn.close()
    
    return render_template('dashboard.html', user=user, messages=messages)

# VULNERABILITY 3: Stored XSS
@app.route('/post_message', methods=['POST'])
def post_message():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    message = request.form['message']  # No sanitization!
    
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    c.execute("INSERT INTO messages (user_id, message, timestamp) VALUES (?,?,?)",
             (session['user_id'], message, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()
    
    return redirect(url_for('dashboard'))

# VULNERABILITY 4: CSRF (No CSRF token protection)
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        recipient = request.form['recipient']
        amount = int(request.form['amount'])
        
        conn = sqlite3.connect('vulnerable.db')
        c = conn.cursor()
        
        # Deduct from sender
        c.execute("UPDATE users SET balance = balance - ? WHERE id=?", 
                 (amount, session['user_id']))
        
        # Add to recipient
        c.execute("UPDATE users SET balance = balance + ? WHERE username=?", 
                 (amount, recipient))
        
        conn.commit()
        conn.close()
        
        return redirect(url_for('dashboard'))
    
    return render_template('transfer.html')

# VULNERABILITY 5: Insecure Direct Object Reference (IDOR)
@app.route('/profile/<int:user_id>')
def profile(user_id):
    # No authorization check! Anyone can view any profile
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    conn.close()
    
    if user:
        return render_template('profile.html', user=user)
    return "User not found"

# VULNERABILITY 6: Information Disclosure
@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    
    # VULNERABLE: Shows full database results including passwords
    sql = f"SELECT * FROM users WHERE username LIKE '%{query}%' OR email LIKE '%{query}%'"
    c.execute(sql)
    results = c.fetchall()
    conn.close()
    
    return render_template('search.html', results=results, query=query)

# VULNERABILITY 7: Weak Session Management
@app.route('/logout')
def logout():
    # Doesn't properly clear session
    session.pop('user_id', None)
    # Doesn't invalidate cookies
    return redirect(url_for('index'))

# Admin panel (supposed to be restricted)
@app.route('/admin')
def admin():
    # VULNERABILITY 8: Missing authentication check
    # Anyone can access if they know the URL
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    conn.close()
    
    return render_template('admin.html', users=users)

# VULNERABILITY 9: Command Injection
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    if request.method == 'POST':
        host = request.form['host']
        # VULNERABLE: Direct command execution
        result = os.popen(f'ping -c 4 {host}').read()
        return render_template('ping.html', result=result)
    
    return render_template('ping.html')

# VULNERABILITY 10: Path Traversal
@app.route('/download')
def download():
    filename = request.args.get('file', '')
    # VULNERABLE: No path validation
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == '__main__':
    init_db()
    # WARNING: Debug mode ON and accessible from all interfaces
    app.run(host='0.0.0.0', port=5000, debug=True)

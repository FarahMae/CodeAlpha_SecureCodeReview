#!/usr/bin/env python3
"""
CodeAlpha Task 3: Secure Coding Review
Vulnerable Flask Web Application for Security Analysis

WARNING: This application contains INTENTIONAL security vulnerabilities
for educational purposes. DO NOT deploy in production environments.

Vulnerabilities Demonstrated:
1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Insecure Authentication
4. Session Management Issues
5. Path Traversal
6. Command Injection
7. Insecure Direct Object Reference
8. Missing Security Headers
9. Hardcoded Credentials
10. Insufficient Input Validation

Author: FarahMae - CodeAlpha Cybersecurity Intern
Purpose: Educational security assessment and remediation demonstration
"""

from flask import Flask, request, render_template_string, session, redirect, url_for, send_file
import sqlite3
import os
import subprocess
import hashlib
import base64

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded Secret Key (Security Misconfiguration)
app.secret_key = "supersecretkey123"  # Never hardcode secrets!

# VULNERABILITY 2: Hardcoded Database Credentials
DB_NAME = "vulnerable_app.db"
ADMIN_PASSWORD = "admin123"  # Hardcoded credentials

# Initialize vulnerable database
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT,
            balance REAL
        )
    ''')
    
    # Create posts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            title TEXT,
            content TEXT,
            private INTEGER DEFAULT 0
        )
    ''')
    
    # Insert vulnerable test data
    cursor.execute("INSERT OR REPLACE INTO users VALUES (1, 'admin', 'admin123', 'admin@example.com', 'admin', 10000.0)")
    cursor.execute("INSERT OR REPLACE INTO users VALUES (2, 'user1', 'password', 'user1@example.com', 'user', 100.0)")
    cursor.execute("INSERT OR REPLACE INTO users VALUES (3, 'testuser', 'test123', 'test@example.com', 'user', 50.0)")
    
    cursor.execute("INSERT OR REPLACE INTO posts VALUES (1, 1, 'Admin Post', 'This is a private admin post', 1)")
    cursor.execute("INSERT OR REPLACE INTO posts VALUES (2, 2, 'User Post', 'This is a public user post', 0)")
    
    conn.commit()
    conn.close()

# VULNERABILITY 3: SQL Injection - No input sanitization
def authenticate_user(username, password):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation allows SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()
        return result
    except Exception as e:
        print(f"Database error: {e}")
        conn.close()
        return None

# VULNERABILITY 4: SQL Injection in search functionality
def search_users(search_term):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # VULNERABLE: SQL injection via search parameter
    query = f"SELECT username, email FROM users WHERE username LIKE '%{search_term}%'"
    
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        return results
    except Exception as e:
        print(f"Search error: {e}")
        conn.close()
        return []

# VULNERABILITY 5: Insecure Direct Object Reference
def get_user_post(post_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # VULNERABLE: No access control checks
    query = f"SELECT * FROM posts WHERE id = {post_id}"
    
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()
        return result
    except Exception as e:
        print(f"Post retrieval error: {e}")
        conn.close()
        return None

@app.route('/')
def home():
    # VULNERABILITY 6: Missing Security Headers
    return render_template_string('''
    <html>
    <head><title>Vulnerable Banking App</title></head>
    <body>
        <h1>Welcome to Vulnerable Bank</h1>
        <p><a href="/login">Login</a></p>
        <p><a href="/search">Search Users</a></p>
        <p><a href="/calculator">Calculator</a></p>
        <p><a href="/file">File Access</a></p>
    </body>
    </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # VULNERABILITY 3: SQL Injection via authentication
        user = authenticate_user(username, password)
        
        if user:
            # VULNERABILITY 7: Session Management Issues
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[4]
            return redirect(url_for('dashboard'))
        else:
            # VULNERABILITY 8: Information Disclosure
            error = f"Login failed for user: {username}"
            return render_template_string('''
            <html>
            <body>
                <h2>Login Failed</h2>
                <p style="color: red;">''' + error + '''</p>
                <form method="post">
                    Username: <input type="text" name="username" value="''' + username + '''"><br>
                    Password: <input type="password" name="password"><br>
                    <input type="submit" value="Login">
                </form>
                <p><a href="/">Back to Home</a></p>
            </body>
            </html>
            ''')
    
    return render_template_string('''
    <html>
    <body>
        <h2>Login</h2>
        <form method="post">
            Username: <input type="text" name="username"><br><br>
            Password: <input type="password" name="password"><br><br>
            <input type="submit" value="Login">
        </form>
        <p>Try: admin/admin123 or user1/password</p>
        <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    ''')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # VULNERABILITY 9: Cross-Site Scripting (XSS)
    username = session.get('username', '')
    
    return render_template_string('''
    <html>
    <body>
        <h2>Dashboard</h2>
        <p>Welcome back, ''' + username + '''!</p>
        <p>Role: ''' + session.get('role', 'user') + '''</p>
        <p><a href="/profile">View Profile</a></p>
        <p><a href="/post/1">View Post</a></p>
        <p><a href="/logout">Logout</a></p>
    </body>
    </html>
    ''')

@app.route('/search')
def search():
    search_term = request.args.get('q', '')
    results = []
    
    if search_term:
        # VULNERABILITY 4: SQL Injection in search
        results = search_users(search_term)
    
    # VULNERABILITY 9: XSS via search parameter
    return render_template_string('''
    <html>
    <body>
        <h2>User Search</h2>
        <form method="get">
            Search: <input type="text" name="q" value="''' + search_term + '''">
            <input type="submit" value="Search">
        </form>
        <p>Search results for: ''' + search_term + '''</p>
        <ul>
        ''' + ''.join([f'<li>{result[0]} - {result[1]}</li>' for result in results]) + '''
        </ul>
        <p>Try searching for: ' OR 1=1 --</p>
        <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    ''')

@app.route('/post/<int:post_id>')
def view_post(post_id):
    # VULNERABILITY 5: Insecure Direct Object Reference
    post = get_user_post(post_id)
    
    if post:
        return render_template_string('''
        <html>
        <body>
            <h2>''' + str(post[2]) + '''</h2>
            <p>''' + str(post[3]) + '''</p>
            <p>Post ID: ''' + str(post[0]) + '''</p>
            <p><a href="/dashboard">Back to Dashboard</a></p>
        </body>
        </html>
        ''')
    else:
        return "Post not found", 404

@app.route('/calculator')
def calculator():
    expression = request.args.get('expr', '')
    result = ''
    
    if expression:
        try:
            # VULNERABILITY 10: Command Injection via eval()
            result = str(eval(expression))  # NEVER use eval() with user input!
        except Exception as e:
            result = f"Error: {str(e)}"
    
    return render_template_string('''
    <html>
    <body>
        <h2>Calculator</h2>
        <form method="get">
            Expression: <input type="text" name="expr" value="''' + expression + '''">
            <input type="submit" value="Calculate">
        </form>
        <p>Result: ''' + result + '''</p>
        <p>Try: 2+2 or __import__('os').system('whoami')</p>
        <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    ''')

@app.route('/file')
def file_access():
    filename = request.args.get('name', '')
    content = ''
    
    if filename:
        try:
            # VULNERABILITY 11: Path Traversal
            with open(filename, 'r') as f:  # No path validation!
                content = f.read()
        except Exception as e:
            content = f"Error reading file: {str(e)}"
    
    return render_template_string('''
    <html>
    <body>
        <h2>File Reader</h2>
        <form method="get">
            Filename: <input type="text" name="name" value="''' + filename + '''">
            <input type="submit" value="Read File">
        </form>
        <pre>''' + content + '''</pre>
        <p>Try: /etc/passwd or ../../../etc/passwd</p>
        <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    ''')

@app.route('/logout')
def logout():
    # VULNERABILITY 12: Insecure Session Management
    session.clear()  # Basic logout, no CSRF protection
    return redirect(url_for('home'))

# VULNERABILITY 13: Debug Mode in Production
if __name__ == '__main__':
    init_db()
    print("🚨 WARNING: This application contains intentional security vulnerabilities!")
    print("   DO NOT use in production environments.")
    print("   Purpose: Educational security assessment")
    print("\n🔍 Vulnerabilities to find:")
    print("   1. SQL Injection (multiple locations)")
    print("   2. Cross-Site Scripting (XSS)")
    print("   3. Command Injection")
    print("   4. Path Traversal")
    print("   5. Insecure Direct Object Reference")
    print("   6. Hardcoded Credentials")
    print("   7. Session Management Issues")
    print("   8. Missing Security Headers")
    print("   9. Information Disclosure")
    print("   10. Insecure Configuration")
    
    # VULNERABILITY: Debug mode enabled
    app.run(debug=True, host='0.0.0.0', port=5000)

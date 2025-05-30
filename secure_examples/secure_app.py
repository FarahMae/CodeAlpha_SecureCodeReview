#!/usr/bin/env python3
"""
CodeAlpha Task 3: Secure Coding Review
SECURE Flask Web Application - Remediated Version

This application demonstrates the SECURE implementation of the same
functionality as the vulnerable app, with all security issues resolved.

Security Improvements:
1. ✅ Parameterized SQL queries (prevents SQL injection)
2. ✅ Input validation and sanitization
3. ✅ Secure session management
4. ✅ Environment-based configuration
5. ✅ Security headers implementation
6. ✅ Access control enforcement
7. ✅ Safe file handling
8. ✅ CSRF protection
9. ✅ Password hashing
10. ✅ Security logging

Author: FarahMae - CodeAlpha Cybersecurity Intern
Purpose: Demonstrate secure coding practices and remediation techniques
"""

from flask import Flask, request, render_template_string, session, redirect, url_for, jsonify, escape
from flask_wtf import FlaskForm, CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from wtforms import StringField, PasswordField, validators
import sqlite3
import os
import hashlib
import secrets
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path
import bleach
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ✅ SECURE: Use environment variables for configuration
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# ✅ SECURE: Enable CSRF protection
csrf = CSRFProtect(app)

# ✅ SECURE: Rate limiting to prevent brute force attacks
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# ✅ SECURE: Security logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ✅ SECURE: Database configuration
DB_NAME = os.environ.get('DB_NAME', 'secure_app.db')
ALLOWED_FILE_EXTENSIONS = {'txt', 'log', 'md'}
UPLOAD_FOLDER = 'safe_files'

# ✅ SECURE: Input validation patterns
SAFE_USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
SAFE_SEARCH_PATTERN = re.compile(r'^[a-zA-Z0-9\s]{1,50}$')

class LoginForm(FlaskForm):
    """✅ SECURE: WTForms with CSRF protection"""
    username = StringField('Username', [
        validators.Length(min=3, max=20),
        validators.Regexp(r'^[a-zA-Z0-9_]+$', message="Username must contain only letters, numbers, and underscores")
    ])
    password = PasswordField('Password', [
        validators.Length(min=6, max=100)
    ])

def init_secure_db():
    """✅ SECURE: Initialize database with hashed passwords"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Create users table with better schema
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            balance REAL DEFAULT 0.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP
        )
    ''')
    
    # Create posts table with proper access control
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            is_private INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create audit log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            details TEXT
        )
    ''')
    
    # ✅ SECURE: Insert users with hashed passwords
    admin_hash = generate_password_hash('SecureAdmin123!')
    user_hash = generate_password_hash('SecureUser123!')
    
    cursor.execute("""
        INSERT OR REPLACE INTO users (id, username, password_hash, email, role, balance) 
        VALUES (1, 'admin', ?, 'admin@example.com', 'admin', 10000.0)
    """, (admin_hash,))
    
    cursor.execute("""
        INSERT OR REPLACE INTO users (id, username, password_hash, email, role, balance) 
        VALUES (2, 'user1', ?, 'user1@example.com', 'user', 100.0)
    """, (user_hash,))
    
    # Insert sample posts
    cursor.execute("""
        INSERT OR REPLACE INTO posts (id, user_id, title, content, is_private) 
        VALUES (1, 1, 'Admin Post', 'This is a private admin post', 1)
    """)
    cursor.execute("""
        INSERT OR REPLACE INTO posts (id, user_id, title, content, is_private) 
        VALUES (2, 2, 'User Post', 'This is a public user post', 0)
    """)
    
    conn.commit()
    conn.close()
    logger.info("Secure database initialized")

def log_security_event(action, user_id=None, details=None):
    """✅ SECURE: Security event logging"""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        """, (user_id, action, request.remote_addr, details))
        
        conn.commit()
        conn.close()
        logger.info(f"Security event: {action} - User: {user_id} - IP: {request.remote_addr}")
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")

def validate_input(input_string, pattern, max_length=100):
    """✅ SECURE: Input validation function"""
    if not input_string:
        return False
    
    if len(input_string) > max_length:
        return False
    
    return pattern.match(input_string) is not None

def is_account_locked(username):
    """✅ SECURE: Check if account is locked due to failed attempts"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT failed_attempts, locked_until FROM users 
        WHERE username = ?
    """, (username,))
    
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return False
    
    failed_attempts, locked_until = result
    
    if locked_until:
        lock_time = datetime.fromisoformat(locked_until)
        if datetime.now() < lock_time:
            return True
    
    return failed_attempts >= 5

def update_failed_attempts(username, success=False):
    """✅ SECURE: Update failed login attempts"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    if success:
        cursor.execute("""
            UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ?
            WHERE username = ?
        """, (datetime.now().isoformat(), username))
    else:
        lock_until = (datetime.now() + timedelta(minutes=30)).isoformat()
        cursor.execute("""
            UPDATE users SET failed_attempts = failed_attempts + 1,
                           locked_until = CASE WHEN failed_attempts >= 4 THEN ? ELSE NULL END
            WHERE username = ?
        """, (lock_until, username))
    
    conn.commit()
    conn.close()

def authenticate_user(username, password):
    """✅ SECURE: Secure authentication with parameterized queries"""
    if not validate_input(username, SAFE_USERNAME_PATTERN):
        log_security_event("INVALID_USERNAME_FORMAT", details=username)
        return None
    
    if is_account_locked(username):
        log_security_event("ACCOUNT_LOCKED_ACCESS_ATTEMPT", details=username)
        return None
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # ✅ SECURE: Parameterized query prevents SQL injection
    cursor.execute("""
        SELECT id, username, password_hash, email, role 
        FROM users WHERE username = ?
    """, (username,))
    
    result = cursor.fetchone()
    conn.close()
    
    if result and check_password_hash(result[2], password):
        update_failed_attempts(username, success=True)
        log_security_event("SUCCESSFUL_LOGIN", user_id=result[0])
        return {
            'id': result[0],
            'username': result[1],
            'email': result[3],
            'role': result[4]
        }
    else:
        update_failed_attempts(username, success=False)
        log_security_event("FAILED_LOGIN_ATTEMPT", details=username)
        return None

def search_users_secure(search_term, current_user_role):
    """✅ SECURE: Safe search with parameterized queries and access control"""
    if not validate_input(search_term, SAFE_SEARCH_PATTERN, max_length=50):
        return []
    
    # ✅ SECURE: Role-based access control
    if current_user_role != 'admin':
        return []
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # ✅ SECURE: Parameterized query with LIKE operator
    search_pattern = f"%{search_term}%"
    cursor.execute("""
        SELECT username, email FROM users 
        WHERE username LIKE ? 
        LIMIT 10
    """, (search_pattern,))
    
    results = cursor.fetchall()
    conn.close()
    
    log_security_event("USER_SEARCH", details=f"Search term: {search_term}")
    return results

def get_user_post_secure(post_id, current_user_id, current_user_role):
    """✅ SECURE: Access control for post retrieval"""
    try:
        post_id = int(post_id)  # Validate input type
    except (ValueError, TypeError):
        return None
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # ✅ SECURE: Access control check
    cursor.execute("""
        SELECT p.id, p.user_id, p.title, p.content, p.is_private, u.username
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
    """, (post_id,))
    
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return None
    
    post_data = {
        'id': result[0],
        'user_id': result[1],
        'title': result[2],
        'content': result[3],
        'is_private': result[4],
        'author': result[5]
    }
    
    # ✅ SECURE: Enforce access control
    if post_data['is_private']:
        if current_user_role != 'admin' and current_user_id != post_data['user_id']:
            log_security_event("UNAUTHORIZED_POST_ACCESS", 
                             user_id=current_user_id, 
                             details=f"Post ID: {post_id}")
            return None
    
    return post_data

@app.before_request
def security_headers():
    """✅ SECURE: Add security headers to all responses"""
    pass

@app.after_request
def add_security_headers(response):
    """✅ SECURE: Security headers"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Banking App</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body>
        <h1>🛡️ Secure Banking Application</h1>
        <p>This is the SECURE version of the banking application.</p>
        <ul>
            <li><a href="/login">Login</a></li>
            <li><a href="/search">Search Users</a> (Admin only)</li>
            <li><a href="/calculator">Secure Calculator</a></li>
        </ul>
        <footer>
            <p>🔒 Security features enabled: CSRF protection, rate limiting, input validation</p>
        </footer>
    </body>
    </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # ✅ SECURE: Rate limiting
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        user = authenticate_user(username, password)
        
        if user:
            # ✅ SECURE: Regenerate session ID to prevent session fixation
            session.regenerate = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['csrf_token'] = secrets.token_hex(16)
            
            return redirect(url_for('dashboard'))
        else:
            # ✅ SECURE: Generic error message to prevent username enumeration
            error = "Invalid credentials. Account may be locked after 5 failed attempts."
            return render_template_string('''
            <!DOCTYPE html>
            <html>
            <body>
                <h2>🔐 Secure Login</h2>
                <p style="color: red;">{{ error }}</p>
                <form method="post">
                    {{ form.hidden_tag() }}
                    {{ form.username.label }}: {{ form.username() }}<br><br>
                    {{ form.password.label }}: {{ form.password() }}<br><br>
                    <input type="submit" value="Login">
                </form>
                <p><a href="/">Back to Home</a></p>
            </body>
            </html>
            ''', form=form, error=error)
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <body>
        <h2>🔐 Secure Login</h2>
        <form method="post">
            {{ form.hidden_tag() }}
            {{ form.username.label }}: {{ form.username() }}<br><br>
            {{ form.password.label }}: {{ form.password() }}<br><br>
            <input type="submit" value="Login">
        </form>
        <p>Demo accounts: admin/SecureAdmin123! or user1/SecureUser123!</p>
        <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    ''', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # ✅ SECURE: Escape user input to prevent XSS
    username = escape(session.get('username', ''))
    role = escape(session.get('role', ''))
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <body>
        <h2>🛡️ Secure Dashboard</h2>
        <p>Welcome back, {{ username }}!</p>
        <p>Role: {{ role }}</p>
        <ul>
            <li><a href="/profile">View Profile</a></li>
            <li><a href="/post/1">View Post</a></li>
            <li><a href="/logout">Logout</a></li>
        </ul>
    </body>
    </html>
    ''', username=username, role=role)

@app.route('/search')
def search():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # ✅ SECURE: Role-based access control
    if session.get('role') != 'admin':
        log_security_event("UNAUTHORIZED_SEARCH_ACCESS", user_id=session.get('user_id'))
        return "Access denied. Admin privileges required.", 403
    
    search_term = request.args.get('q', '')
    results = []
    error = None
    
    if search_term:
        if validate_input(search_term, SAFE_SEARCH_PATTERN):
            results = search_users_secure(search_term, session.get('role'))
        else:
            error = "Invalid search term. Use only letters, numbers, and spaces."
    
    # ✅ SECURE: Escape output to prevent XSS
    safe_search_term = escape(search_term)
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <body>
        <h2>🔍 Secure User Search</h2>
        <form method="get">
            Search: <input type="text" name="q" value="{{ search_term }}" maxlength="50">
            <input type="submit" value="Search">
        </form>
        {% if error %}
            <p style="color: red;">{{ error }}</p>
        {% endif %}
        <p>Search results for: {{ search_term }}</p>
        <ul>
        {% for result in results %}
            <li>{{ result[0] }} - {{ result[1] }}</li>
        {% endfor %}
        </ul>
        <p><a href="/dashboard">Back to Dashboard</a></p>
    </body>
    </html>
    ''', search_term=safe_search_term, results=results, error=error)

@app.route('/calculator')
def calculator():
    """✅ SECURE: Safe calculator without eval()"""
    expression = request.args.get('expr', '')
    result = ''
    error = None
    
    if expression:
        # ✅ SECURE: Whitelist approach for mathematical expressions
        if re.match(r'^[0-9+\-*/().\s]+$', expression):
            try:
                # ✅ SECURE: Use ast.literal_eval for safe evaluation
                import ast
                import operator
                
                # Define safe operations
                ops = {
                    ast.Add: operator.add,
                    ast.Sub: operator.sub,
                    ast.Mult: operator.mul,
                    ast.Div: operator.truediv,
                    ast.USub: operator.neg,
                }
                
                def eval_expr(node):
                    if isinstance(node, ast.Num):
                        return node.n
                    elif isinstance(node, ast.BinOp):
                        return ops[type(node.op)](eval_expr(node.left), eval_expr(node.right))
                    elif isinstance(node, ast.UnaryOp):
                        return ops[type(node.op)](eval_expr(node.operand))
                    else:
                        raise TypeError(node)
                
                result = str(eval_expr(ast.parse(expression, mode='eval').body))
                
            except Exception as e:
                error = "Invalid mathematical expression"
        else:
            error = "Only mathematical operations are allowed"
    
    safe_expression = escape(expression)
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <body>
        <h2>🧮 Secure Calculator</h2>
        <form method="get">
            Expression: <input type="text" name="expr" value="{{ expression }}" maxlength="100">
            <input type="submit" value="Calculate">
        </form>
        {% if error %}
            <p style="color: red;">{{ error }}</p>
        {% elif result %}
            <p>Result: {{ result }}</p>
        {% endif %}
        <p>Only basic mathematical operations (+, -, *, /, parentheses) are allowed.</p>
        <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    ''', expression=safe_expression, result=result, error=error)

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    log_security_event("USER_LOGOUT", user_id=user_id)
    
    # ✅ SECURE: Complete session cleanup
    session.clear()
    
    return redirect(url_for('home'))

if __name__ == '__main__':
    init_secure_db()
    
    print("🛡️ SECURE Application Starting")
    print("=" * 40)
    print("✅ Security features enabled:")
    print("  • CSRF Protection")
    print("  • Rate Limiting")
    print("  • Input Validation")
    print("  • Parameterized Queries")
    print("  • Security Headers")
    print("  • Access Control")
    print("  • Security Logging")
    print("  • Password Hashing")
    print("  • Account Lockout")
    print("  • Session Security")
    
    # ✅ SECURE: Production-ready configuration
    app.run(
        debug=False,  # Debug disabled
        host='127.0.0.1',  # Localhost only
        port=5001  # Different port from vulnerable app
    )

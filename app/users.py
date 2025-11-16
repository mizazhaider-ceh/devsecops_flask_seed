# app/users.py (SECURE)
import sqlite3
import re
from flask import request, jsonify
from app import app

def validate_username(username):
    """Validate username: 3-20 chars, alphanumeric + underscore only."""
    if not username or len(username) < 3 or len(username) > 20:
        raise ValueError("Username must be 3-20 characters")
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        raise ValueError("Invalid characters in username")
    return username

@app.route('/user')
def get_user():
    """Securely retrieve user with parameterized queries."""
    username = request.args.get('username', '')
    
    try:
        username = validate_username(username)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    
    #  SECURE: Parameterized query - parameters treated as DATA, not CODE
    query = "SELECT id, username, email FROM users WHERE username = ?"
    cur = conn.cursor()
    cur.execute(query, (username,))  # Parameters passed separately
    
    rows = cur.fetchall()
    conn.close()
    
    users = [dict(row) for row in rows]
    return jsonify({"success": True, "users": users}) if users else jsonify({"success": False}), 404
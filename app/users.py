import sqlite3
from flask import request, jsonify
from app import app

@app.route('/user')
def get_user():
    username = request.args.get('username', '')
    # INSECURE: SQL built via string formatting (SQLi)
    conn = sqlite3.connect(app.config['DATABASE'])
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cur = conn.cursor()
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return jsonify(rows)
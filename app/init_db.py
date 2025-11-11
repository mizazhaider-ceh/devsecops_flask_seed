import sqlite3
from app.config import DATABASE

def init_db():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    cur.execute("INSERT INTO users (username, password) VALUES ('admin', 'password')")
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
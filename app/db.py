import sqlite3

conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    hashed_password TEXT,
    public_key TEXT,
    encrypted_private_key TEXT
)
""")
conn.commit()

def get_user(username: str):
    return cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

def add_user(username: str, hashed_password: str, public_key: str, encrypted_private_key: str):
    cursor.execute("INSERT INTO users VALUES (?, ?, ?, ?)", (
        username, hashed_password, public_key, encrypted_private_key
    ))
    conn.commit()

import sqlite3

def find_user(username):
    connection = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE username = ?"
    return connection.execute(query, (username,)).fetchall()
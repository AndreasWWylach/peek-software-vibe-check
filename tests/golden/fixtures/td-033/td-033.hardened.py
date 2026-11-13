def get_order(cursor, email: str):
    cursor.execute("SELECT * FROM orders WHERE email = %s", (email,))
    return cursor.fetchall()

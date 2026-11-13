def get_order(cursor, email: str):
    cursor.execute("SELECT * FROM orders WHERE email = " + email)
    return cursor.fetchall()

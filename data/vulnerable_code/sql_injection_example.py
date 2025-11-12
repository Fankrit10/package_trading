import sqlite3


def get_user_by_username(username: str):
    """
    Vulnerable function that uses string concatenation for SQL queries.
    This allows SQL injection attacks.
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username = '{username}'"

    cursor.execute(query)
    result = cursor.fetchone()

    conn.close()
    return result


def search_products(search_term: str):
    """
    Another vulnerable SQL query using string formatting.
    """
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()

    query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"

    cursor.execute(query)
    results = cursor.fetchall()

    conn.close()
    return results

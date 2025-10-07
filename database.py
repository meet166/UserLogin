import pymysql

def get_connection():
    try:
        conn = pymysql.connect(
            host="localhost",
            user="root",
            password="root",
            database="db",
            cursorclass=pymysql.cursors.DictCursor
        )
        return conn
    except Exception as e:
        print("Database connection error:", e)
        return None
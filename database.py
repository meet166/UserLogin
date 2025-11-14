import aiomysql

async def get_connection():
    return await aiomysql.connect(
        host="localhost",
        port=3306,
        user="root",
        password="root",
        db="db1",
        autocommit=True
    )
import aiomysql

async def get_connection():
    return await aiomysql.connect(
        host="localhost",
        user="root",
        password="root",
        db="db",
        autocommit=True
    )
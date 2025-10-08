from database import get_connection
import pymysql
import base64
import hashlib
from Crypto.Cipher import AES
import os
import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import math
import secrets
import string

security = HTTPBearer()

# Encryption Setup
class Encryptor:
    def __init__(self):
        self.enc_method = "aes-256-cbc"
        self.enc_key = os.getenv("self.enc_key", "1234")
        self.enc_seckey = os.getenv("self.enc_seckey", "xhargargrgaergagsreg4dg")
        hex_key = hashlib.sha256(self.enc_key.encode()).hexdigest()
        self.gen_key = hex_key[:32].encode("utf-8")
        hex_iv = hashlib.sha256(self.enc_seckey.encode()).hexdigest()
        self.iv = hex_iv[:16].encode("utf-8")

    def clean_encode(self, data):
        return data.replace("+", "-").replace("/", "_").rstrip("=")

    def clean_decode(self, data):
        data = data.replace("-", "+").replace("_", "/")
        return data + "=" * (-len(data) % 4)

    def encryptString(self, text):
        cipher = AES.new(self.gen_key, AES.MODE_CBC, iv=self.iv)
        padded_text = self._pkcs7_pad(text.encode())
        encrypted = cipher.encrypt(padded_text)

        b64_once = base64.b64encode(encrypted).decode("utf-8")
        b64_twice = base64.b64encode(b64_once.encode()).decode("utf-8")

        return self.clean_encode(b64_twice)

    def decryptString(self, encoded):
        decoded_once = base64.b64decode(self.clean_decode(encoded)).decode("utf-8")

        cipher = AES.new(self.gen_key, AES.MODE_CBC, iv=self.iv)
        decrypted = cipher.decrypt(base64.b64decode(decoded_once))
        return self._pkcs7_unpad(decrypted).decode("utf-8").strip()

    def _pkcs7_pad(self, data):
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len]) * pad_len

    def _pkcs7_unpad(self, data):
        pad_len = data[-1]
        return data[:-pad_len]

encryptor = Encryptor()

# JWT Setup
JWT_SECRET = os.getenv("JWT_SECRET", "xhargargrgaergagsreg4dg")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 30 * 24 * 60

def create_jwt_token(user_id: int, email: str, password_changed_at: datetime):
    payload = {
        "sub": str(user_id),
        "email": email,
        "password_changed_at": password_changed_at.isoformat(),
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_jwt_token(token: str):
    print("Token received:", token)
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = int(payload.get("sub"))
        token_pwd_time = datetime.fromisoformat(payload.get("password_changed_at"))

        conn = get_connection()
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT password_changed_at FROM user WHERE id=%s", (user_id,))
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=401, detail="User not found")
            
            db_pwd_time = row["password_changed_at"]
            
        if token_pwd_time.replace(microsecond=0) < db_pwd_time.replace(microsecond=0):
            raise HTTPException(status_code=401, detail="Token expired due to password change")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    finally:
        conn.close()
        
# Change Password
async def change_password_and_generate_token(user_id: int, old_password: str, new_password: str = None):
    conn = get_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT password, email FROM user WHERE id=%s", (user_id,))
            user = cursor.fetchone()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            if encryptor.encryptString(old_password) != user["password"]:
                raise HTTPException(status_code=401, detail="Old password incorrect")

            if not new_password:
                alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
                new_password = ''.join(secrets.choice(alphabet) for _ in range(12))

            encrypted_password = encryptor.encryptString(new_password)
            now = datetime.utcnow()
            cursor.execute(
                "UPDATE user SET password=%s, password_changed_at=%s WHERE id=%s",
                (encrypted_password, now, user_id)
            )
            conn.commit()

        new_token = create_jwt_token(user_id, user["email"], now)
        return {
            "message": "Password changed successfully",
            "new_password": new_password,
            "token": new_token
        }
    finally:
        conn.close()
        
# Auth & User
def login_user(name: str, email: str, password: str):
    conn = get_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT * FROM user WHERE name=%s AND email=%s", (name, email))
            user = cursor.fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        stored_pass = user["password"]
        if encryptor.encryptString(password) == stored_pass:
            token = create_jwt_token(user_id=user["id"], email=user["email"], password_changed_at=user["password_changed_at"])
            return {"message": "Login successful", "token": token}
        else:
            raise HTTPException(status_code=401, detail="Invalid password")
    finally:
        conn.close()
        
# Get Current User
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    if token.startswith("Bearer "):
        token = token[7:]

    payload = decode_jwt_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user_id = int(payload.get("sub"))
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user_id = int(user_id)

    conn = get_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT * FROM user WHERE id=%s", (user_id,))
            user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        new_token = create_jwt_token(user_id, user["email"], user["password_changed_at"])
        return user
    finally:
        conn.close()

# Get All Brands
async def get_all_brands():
    conn = get_connection()
    if conn is None:
        return {"error": "Database connection failed"}
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT * FROM brand")
            rows = cursor.fetchall()
        return rows
    finally:
        if conn:
            conn.close()

# Get All categories
async def get_all_categories():
    conn = get_connection()
    if conn is None:
        return {"error": "Database connection failed"}
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT * FROM category")
            rows = cursor.fetchall()
        return rows 
    finally:
        if conn:
            conn.close()

# Get All categories by nested structure
async def get_all_categories_by_nested():
    conn = get_connection()
    if conn is None:
        return {"error": "Database connection failed"}
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT * FROM category")
            rows = cursor.fetchall()

        category_nested = {}
        for cat in rows:
            category_nested[cat["id"]] = cat

        for cat in rows:
            cat["child"] = []

        root_categories = []

        for cat in rows:
            parent_id = cat.get("parent_id")
            if parent_id and parent_id in category_nested:
                category_nested[parent_id]["child"].append(cat)
            else:
                root_categories.append(cat)

        return root_categories

    finally:
        if conn:
            conn.close()

# Get All category by parentID
async def get_all_category_by_parentID(parent_id: int):
    conn = get_connection()
    if conn is None:
        return {"error": "Database connection failed"}
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            sql = "SELECT * FROM category WHERE parent_id = %s"
            cursor.execute(sql, (parent_id,))
            rows = cursor.fetchall()
        return rows
    finally:
        if conn:
            conn.close()

# Get categories By pageLimit
async def get_categories_pages(page: int = 1, page_size: int = 20):
    conn = get_connection()
    if conn is None:
        return {"error": "Database connection failed"}

    try:
        with conn.cursor() as cursor:

            cursor.execute("SELECT COUNT(*) as total FROM category")
            total_records = cursor.fetchone()["total"]

            offset = (page - 1) * page_size

            sql = "SELECT * FROM category LIMIT %s OFFSET %s"
            cursor.execute(sql, (page_size, offset))
            rows = cursor.fetchall()

        return {
            "page": page,
            "page_size": page_size,
            "total_records": total_records,
            "total_pages":  math.ceil(total_records / page_size),
            "data": rows
        }
    finally:
        conn.close()

# Get products By pageLimit
async def get_products_pages(page: int = 1, page_size: int = 20):
    conn = get_connection()
    if conn is None:
        return {"error": "Database connection failed"}

    try:
        with conn.cursor() as cursor:

            cursor.execute("SELECT COUNT(*) as total FROM product")
            total_records = cursor.fetchone()["total"]

            offset = (page - 1) * page_size

            sql = "SELECT * FROM product LIMIT %s OFFSET %s"
            cursor.execute(sql, (page_size, offset))
            rows = cursor.fetchall()

        return {
            "page": page,
            "page_size": page_size,
            "total_records": total_records,
            "total_pages":  math.ceil(total_records / page_size),
            "data": rows
        }
    finally:
        conn.close()
    
# Get All attributes
async def get_all_attributes():
    conn = get_connection()
    if conn is None:
        return {"error": "Database connection failed"}
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT * FROM attribute")
            rows = cursor.fetchall()
        return rows
    finally:
        if conn:
            conn.close()
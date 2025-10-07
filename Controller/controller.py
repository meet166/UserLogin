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

security = HTTPBearer()

class Encryptor:
    def __init__(self):
        self.enc_method = "aes-256-cbc"
        self.enc_key = os.getenv("ENCRYPTION_KEY", "1234")
        self.enc_seckey = os.getenv("ENCRYPTION_SECRET_KEY", "xhargargrgaergagsreg4dg")
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

JWT_SECRET = os.getenv("JWT_SECRET", "xhargargrgaergagsreg4dg")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 30 * 24 * 60

def create_jwt_token(user_id: int, email: str):
    payload = {
        "sub": str(user_id),
        "email": email,
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_jwt_token(token: str):
    print("Token received:", token)
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        print("JWT InvalidTokenError:", e)
        raise HTTPException(status_code=401, detail="Invalid token")

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
            token = create_jwt_token(user_id=user["id"], email=user["email"])
            return {"message": "Login successful", "token": token}
        else:
            raise HTTPException(status_code=401, detail="Invalid password")
    finally:
        conn.close()

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
        return user
    finally:
        conn.close()
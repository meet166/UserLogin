from database import get_connection
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
from aiomysql.cursors import DictCursor


security = HTTPBearer()

# Encryption Setup
class Encryptor:
    def __init__(self):
        self.enc_method = "AES-256-CBC"
        self.enc_key = os.getenv("self.enc_key", "Rencom@roup@LLC!!$()!rec^")
        self.enc_seckey = os.getenv("self.enc_seckey", "NDN4aTZEcTFSTWVOc2ZGQVRleHdybER0dzZ5NEQ0TEd3MU5WdXZ0Wk1waz0")
        hex_key = hashlib.sha256(self.enc_key.encode()).hexdigest()
        self.gen_key = hex_key[:32].encode("utf-8")
        hex_iv = hashlib.sha256(self.enc_seckey.encode()).hexdigest()
        self.iv = hex_iv[:16].encode("utf-8")

    def clean_encode(self, data):
        return data.replace("+", "-").replace("/", "_").rstrip("=")

    def clean_decode(self, data):
        data = data.replace("-", "+").replace("_", "/")
        return data + "=" * (-len(data) % 4)
    
    def _pkcs7_pad(self, data):
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len]) * pad_len

    def _pkcs7_unpad(self, data):
        pad_len = data[-1]
        return data[:-pad_len]

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

encryptor = Encryptor()

# JWT Setup
JWT_SECRET = os.getenv("JWT_SECRET", "NDN4aTZEcTFSTWVOc2ZGQVRleHdybER0dzZ5NEQ0TEd3MU5WdXZ0Wk1waz0")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 30 * 24 * 60   # 30 days

def create_jwt_token(user_id: int, email: str, password_changed_at: datetime):
    payload = {
        "sub": str(user_id),
        "email": email,
        "password_changed_at": password_changed_at.isoformat(),
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def decode_jwt_token(token: str):
    print("Token received:", token)
    conn = None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = int(payload.get("sub"))
        token_pwd_time = datetime.fromisoformat(payload.get("password_changed_at"))

        conn = await get_connection()
        
        async with conn.cursor(DictCursor) as cursor:
            await cursor.execute("SELECT password_changed_at FROM user WHERE id=%s", (user_id,))
            row = await cursor.fetchone()
            if not row:
                raise HTTPException(status_code=401, detail="User not found")

            db_pwd_time = row["password_changed_at"].replace(microsecond=0)
            token_pwd_time = token_pwd_time.replace(microsecond=0)
            tolerance = timedelta(seconds=1)

        if token_pwd_time + tolerance < db_pwd_time:
            raise HTTPException(status_code=401, detail="Token expired due to password change")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    finally:
        if conn is not None:
            conn.close()
            
# Auth & User
async def login_user(name: str, email: str, password: str):
    conn = await get_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        async with conn.cursor(DictCursor) as cursor:
            await cursor.execute("""
                SELECT *
                FROM user 
                WHERE name = %s 
                    AND email = %s
                    AND is_deleted = 0
                    AND status = 1
                    AND allow_access_renark = 1
                """,
                (name, email))
            user = await cursor.fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        stored_pass = user["password"]
        input_encrypted = encryptor.encryptString(password)

        if input_encrypted == stored_pass:
            token = create_jwt_token(user_id=user["id"], email=user["email"], password_changed_at=user["password_changed_at"])
            return {"message": "Login successful", "token": token}
        else:
            raise HTTPException(status_code=401, detail="Invalid password")
    finally:
        if conn:
            conn.close()

# Change Password
async def change_password_and_generate_token(user_id: int, old_password: str, new_password: str = None):
    conn = await get_connection()
    try:
        async with conn.cursor(DictCursor) as cursor:
            await cursor.execute("SELECT password, email FROM user WHERE id=%s", (user_id,))
            user = await cursor.fetchone()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            if encryptor.encryptString(old_password) != user["password"]:
                raise HTTPException(status_code=401, detail="Old password incorrect")

            if not new_password:
                alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
                new_password = ''.join(secrets.choice(alphabet) for _ in range(12))

            encrypted_password = encryptor.encryptString(new_password)
            now = datetime.utcnow()
            await cursor.execute(
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
        
# Get Current User
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    if token.startswith("Bearer "):
        token = token[7:]

    payload = await decode_jwt_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user_id = int(payload.get("sub"))
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user_id = int(user_id)

    conn = await get_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        async with conn.cursor(DictCursor) as cursor:
            await cursor.execute("""
                    SELECT *
                    FROM user 
                    WHERE id=%s
                        AND is_deleted = 0
                        AND status = 1
                        AND allow_access_renark = 1
                    """, 
                    (user_id,))
            user = await cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        new_token = create_jwt_token(user_id, user["email"], user["password_changed_at"])
        return user
    finally:
        conn.close()

# Get All Brands
async def get_all_brands():
    conn = await get_connection()
    if conn is None:
        return {"error": "Database connection failed"}
    try:
        async with conn.cursor(DictCursor) as cursor:
            await cursor.execute("""
                    SELECT *
                    FROM brand
                    WHERE status = 1
                        AND is_deleted = 0
                    """)
            rows = await cursor.fetchall()
        return rows
    finally:
        if conn:
            conn.close()

# Get All categories
async def get_all_categories():
    conn = await get_connection()
    if conn is None:
        return {"error": "Database connection failed"}
    try:
        async with conn.cursor(DictCursor) as cursor:
            await cursor.execute("""
                    SELECT *
                    FROM category
                    WHERE status = 1
                        AND is_deleted = 0
                    """)
            rows = await cursor.fetchall()
        return rows 
    finally:
        if conn:
            conn.close()

# Get All categories by nested structure
async def get_all_categories_by_nested():
    conn = await get_connection()
    if conn is None:
        return {"error": "Database connection failed"}
    try:
        async with conn.cursor(DictCursor) as cursor:
        # main query to fetch categories
            await cursor.execute("""
                    SELECT *
                    FROM category
                    WHERE status = 1
                        AND is_deleted = 0
                    """)
            rows = await cursor.fetchall()

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
    conn = await get_connection()
    if conn is None:
        return {"error": "Database connection failed"}
    try:
        async with conn.cursor(DictCursor) as cursor:
            sql = """SELECT *
                    FROM category
                    WHERE status = 1
                        AND is_deleted = 0
                        AND parent_id = %s"""
            await cursor.execute(sql, (parent_id,))
            rows = await cursor.fetchall()
        return rows
    finally:
        if conn:
            conn.close()

# Get categories By pageLimit
async def get_categories_pages(page: int = 1, page_size: int = 20):
    conn = await get_connection()
    if conn is None:
        return {"error": "Database connection failed"}

    try:
        async with conn.cursor(DictCursor) as cursor:
        # Count total active categories
            await cursor.execute("SELECT COUNT(*) as total FROM category WHERE status = 1 AND is_deleted = 0")
            row = await cursor.fetchone()
            total_records = row["total"]

        # if no categories found
            if total_records == 0:
                return {
                    "page": page,
                    "page_size": page_size,
                    "total_records": 0,
                    "total_pages": 0,
                    "has_previous": False,
                    "has_next": False,
                    "data": []
                }
        
        # Pagination checks        
            total_pages = math.ceil(total_records / page_size)
            if page > total_pages:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid page number. Max pages = {total_pages}"
                )
            offset = (page - 1) * page_size
         
        # main query to fetch categories   
            sql = """
                SELECT *
                FROM category
                WHERE status = 1 
                    AND is_deleted = 0
                ORDER BY id ASC
                LIMIT %s OFFSET %s
            """
            await cursor.execute(sql, (page_size, offset))
            rows = await cursor.fetchall()
            
        return {
            "page": page,
            "page_size": page_size,
            "total_records": total_records,
            "total_pages": total_pages,
            "has_previous": page > 1,
            "has_next": page < total_pages,
            "data": rows
        }
    finally:
        conn.close()
        
# Get products By pageLimit
async def get_products_pages(page: int = 1, page_size: int = 64):
    conn = await get_connection()
    if conn is None:
        return {"error": "Database connection failed"}

    try:
        async with conn.cursor(DictCursor) as cursor:
        # Count total active products
            await cursor.execute("SELECT COUNT(*) as total FROM product WHERE status = 1 AND is_deleted = 0")
            row = await cursor.fetchone()
            total_records = row["total"]
        
        # if no products found
            if total_records == 0:
                return {
                    "page": page,
                    "page_size": page_size,
                    "total_records": 0,
                    "total_pages": 0,
                    "has_previous": False,
                    "has_next": False,
                    "data": []
                }
        
        # Pagination checks       
            total_pages = math.ceil(total_records / page_size)
            if page > total_pages:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid page number. Max pages = {total_pages}"
                )
            offset = (page - 1) * page_size
        
        # main query to fetch products    
            sql = """
                SELECT *
                FROM product
                WHERE status = 1
                    AND is_deleted = 0
                ORDER BY id ASC
                LIMIT %s OFFSET %s
            """
            await cursor.execute(sql, (page_size, offset))
            rows = await cursor.fetchall()
            
        return {
            "page": page,
            "page_size": page_size,
            "total_records": total_records,
            "total_pages": total_pages,
            "has_previous": page > 1,
            "has_next": page < total_pages,
            "data": rows
        }
    finally:
        conn.close()
    
# Get All attributes By page
async def get_all_attributes(page: int = 1, page_size: int = 64):
    conn = await get_connection()
    if conn is None:
        return {"error": "Database connection failed"}
    
    try:
        async with conn.cursor(DictCursor) as cursor:
        # Count total active attributes
            await cursor.execute("SELECT COUNT(*) as total FROM attribute WHERE status = 1 AND is_deleted = 0")
            row = await cursor.fetchone()
            total_records = row["total"]

        # if no attributes found
            if total_records == 0:
                return {
                    "page": page,
                    "page_size": page_size,
                    "total_records": 0,
                    "total_pages": 0,
                    "has_previous": False,
                    "has_next": False,
                    "data": []
                }
        # Pagination checks    
            total_pages = math.ceil(total_records / page_size)
            if page > total_pages:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid page number. Max pages = {total_pages}"
                )
            offset = (page - 1) * page_size
            
        # main query to fetch attributes
            sql = """
                SELECT *
                FROM attribute
                WHERE status = 1
                    AND is_deleted = 0
                ORDER BY id ASC
                LIMIT %s OFFSET %s
            """
            await cursor.execute(sql, (page_size, offset))
            rows = await cursor.fetchall()
            
        return {
            "page": page,
            "page_size": page_size,
            "total_records": total_records,
            "total_pages": total_pages,
            "has_previous": page > 1,
            "has_next": page < total_pages,
            "data": rows
        }
    finally:
        conn.close()
        
# Get All Attribute_group
async def get_all_attribute_group():
    conn = await get_connection()
    if conn is None:
        return {"error": "Database connection failed"}
    try:
        async with conn.cursor(DictCursor) as cursor:
            await cursor.execute("""
                    SELECT *
                    FROM attribute_group
                    WHERE status = 1
                        AND is_deleted = 0
                    """)
            rows = await cursor.fetchall()
        return rows
    finally:
        if conn:
            conn.close()
    
# Get Merge All Product with related data
async def get_merge_all_product(page: int = 1, page_size: int = 64):
    page_size = min(page_size, 500)
    offset = (page - 1) * page_size

    conn = await get_connection()
    if conn is None:
        return {"error": "Database connection failed"}
    try:
        async with conn.cursor(DictCursor) as cursor:
        # Count total active products
            await cursor.execute("""
                SELECT COUNT(*) AS total
                FROM product p
                WHERE p.status = 1
                AND p.is_deleted = 0
            """)
            row = await cursor.fetchone()
            total_records = row["total"]

        # If no products found
            if total_records == 0:
                return {
                    "page": page,
                    "page_size": page_size,
                    "total_records": 0,
                    "total_pages": 0,
                    "has_previous": False,
                    "has_next": False,
                    "data": []
                }
        
        # Pagination checks
            total_pages = math.ceil(total_records / page_size)
            if page > total_pages:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid page number. Max pages = {total_pages}"
                )
        # Prepare query parameters
            brandID = [1, 7]
            placeholders = ','.join(['%s'] * len(brandID))
            defaultlang = 1
            today = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Main query to fetch merged product data    
            sql = f"""
                SELECT 
                    p.id,
                    p.brand_id AS brandId,
                    p.base_price AS basePrice,
                    p.sale_price AS salePrice,
                    p.msrp_price AS msrpPrice,
                    p.main_image AS mainImage,
                    p.sku,
                    p.status AS productStatus,
                    p.created_date AS productCreateDate,
                    p.updated_date AS productUpdateDate,
                    p.sku_group AS skuGroup,
                    p.slug,
                    p.piece,
                    p.weight,
                    p.width,
                    p.depth,
                    p.height,
                    p.length,
                    p.tax_flag AS taxFlag,
                    p.tax_id AS taxId,
                    p.related_product_id AS relatedProductId,
                    p.sort_order AS productSortOrder,
                    p.dealer_designated_sku	AS reverseSku,
                    
                    m.id AS markingId,
                    m.name AS markingName,
                    m.ribbon_details, 
                    m.display_position AS markingDisplayPosition,
                    m.display_on_filter AS markingDisplayOnFilter,
                    m.sort_order AS markingSortOrder,
                    
                    pl.name AS productName,
                    pl.short_description AS ShortDescription,
                    pl.full_description AS FullDescription,
                    pl.bullet_features AS BulletFeatures,
                    pl.product_tags AS ProductTags,
                    pl.advance_dimension AS AdvanceDimension,

                    COALESCE(
                        CASE
                            WHEN COALESCE(pm.custom_price, 0) > 0 THEN pm.custom_price
                            WHEN COALESCE(rp.column_value, 0) > 0 THEN rp.column_value
                            WHEN GREATEST(COALESCE(p.sale_price, 0), COALESCE(mp.column_value, 0)) > 0
                                THEN GREATEST(COALESCE(p.sale_price, 0), COALESCE(mp.column_value, 0))
                            ELSE 0
                        END,
                    0) AS final_price
                    
                FROM product p
                
                LEFT JOIN product_lang pl
                    ON pl.product_ref_id = p.ctb_ref_id
                            
                LEFT JOIN product_pricing rp
                    ON rp.product_id = p.id
                    AND rp.column_key = 'retail_price'
                
                LEFT JOIN product_pricing mp
                    ON mp.product_id = p.id
                    AND mp.column_key = 'map_price'

                LEFT JOIN product_marking pm
                    ON p.id = pm.product_id
                    AND pm.status = 1 
                    AND pm.is_deleted = 0
                    AND (
                        pm.showalways = 1
                        OR (
                            (pm.start_date IS NULL OR pm.start_date <= %s)
                            AND (pm.end_date IS NULL OR pm.end_date >= %s)
                        )
                    )
                                
                LEFT JOIN marking m
                    ON pm.marking_id = m.id
                    AND m.status = 1 
                    AND m.is_deleted = 0
                
                LEFT JOIN language l
                    ON pl.lang_ref_id = l.ctb_ref_id
                    AND l.id = %s
                    
                WHERE
                    p.status = 1 
                        AND p.is_deleted = 0
                        AND p.brand_id IN ({placeholders})
                        AND p.base_price > 0
                    ORDER BY p.id
                    LIMIT %s OFFSET %s
            """
            params =[today, today, defaultlang] + brandID + [page_size, offset]
            await cursor.execute(sql, params)
            results = await cursor.fetchall()
            
        return {
            "page": page,
            "page_size": page_size,
            "total_records": total_records,
            "total_pages": math.ceil(total_records / page_size),
            "has_previous": page > 1,
            "has_next": page < total_pages,
            "data": results
        }
        
    finally:
        if conn:
            conn.close()
            
#Get Merge All Brands with related data
async def get_merge_all_brands():
    conn = await get_connection()
    if conn is None:
        return {"error": "Database connection failed"}
    try:
        async with conn.cursor(DictCursor) as cursor:
            
        # main query to fetch brands with related data
            sql = """
            SELECT
                b.*,
                bl.lang_ref_id AS brand_lang_ref_id,
                bl.name AS brand_name,
                bl.description,
                bl.bottom_content,
                bl.meta_title,
                bl.meta_description,
                bl.meta_keyword,
                bl.is_dialect

                FROM brand b
                LEFT JOIN brand_lang bl ON b.ctb_ref_id = bl.brand_ref_id
                
                WHERE b.status = 1
                AND b.is_deleted = 0
                ORDER BY b.id
            """
            await cursor.execute(sql)
            rows = await cursor.fetchall()
        return rows
    finally:
        if conn:
            conn.close()
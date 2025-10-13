from fastapi import APIRouter, Depends, Query
from Controller.controller import login_user, get_current_user, get_all_brands, get_all_category_by_parentID, get_categories_pages, get_all_categories, get_all_categories_by_nested, get_products_pages, change_password_and_generate_token, get_all_attributes, get_merge_all_product, get_merge_all_brands, get_all_attribute_group
from pydantic import BaseModel, EmailStr
from typing import Optional

user_router = APIRouter()
auth_router = APIRouter(
    dependencies=[Depends(get_current_user)]
)

# Models 
class LoginRequest(BaseModel):
    name: str
    email: Optional[EmailStr] = None
    password: str
class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: Optional[str] = None

# User Routes
@user_router.post("/login")
def user_login(req: LoginRequest):
    return login_user(req.name, req.email, req.password)

# Protected Routes
@auth_router.post("/changePassword")
async def user_change_password(
    req: ChangePasswordRequest, 
    current_user: dict = Depends(get_current_user)
):
    result = await change_password_and_generate_token(
        current_user["id"],
        req.old_password,
        req.new_password
    )
    return result

@auth_router.get("/user")
async def user_details(current_user: dict = Depends(get_current_user)):
    return current_user

# get All Brands
@auth_router.get("/getAllBrands")
async def get_Brands():
    return await get_all_brands()

# Get All Categories
@auth_router.get("/getAllCategories")
async def get_All_Categories():
    return await get_all_categories()

# Get All Categories with nested structure
@auth_router.get("/getAllCategoriesByNested")
async def get_Categories_Nested_Structure():
    return await get_all_categories_by_nested()

# Get Category By ParentID
@auth_router.get("/getCategoryByParentID")
async def get_Category_By_ProductID(parent_id: int):
    return await get_all_category_by_parentID(parent_id)

# Get Categories with pageByLimit
@auth_router.get("/getCategoryByPagesLimit")
async def get_category_by_page_limit(
    page: int = Query(1, ge=1),
    page_size: int = Query(ge=1, le=500)):
    return await get_categories_pages(page, page_size)

# Get products with pageByLimit
@auth_router.get("/getProductByPagesLimit")
async def get_product_by_page_limit(
    page: int = Query(1, ge=1),
    page_size: int = Query(64, ge=1, le=500)):
    return await get_products_pages(page, page_size)

# Get All Attributes
@auth_router.get("/getAllAttributes")
async def get_All_Attributes(
    page: int = Query(1, ge=1),
    page_size: int = Query(64, ge=1, le=500)):
    return await get_all_attributes(page, page_size)

# Get All Attribute Group
@auth_router.get("/getAllAttributeGroup")
async def get_All_Attribute_Group():
    return await get_all_attribute_group()

# Get Merge All Product with related data
@auth_router.get("/getMergerAllProduct")
async def get_Merge_All_Product(
    page: int = Query(1, ge=1),
    page_size: int = Query(64, ge=1, le=500)):
    return await get_merge_all_product(page, page_size)

# Get Merge All Brands with related data
@auth_router.get("/getMergeAllBrands")
async def get_Merge_All_Brands():
    return await get_merge_all_brands()
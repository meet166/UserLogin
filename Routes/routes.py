from fastapi import APIRouter, Depends, Query
from Controller.controller import login_user, get_current_user, get_all_brands, get_all_category_by_parentID, get_categories_pages, get_all_categories, get_all_categories_by_nested
from pydantic import BaseModel, EmailStr
from typing import Optional

user_router = APIRouter()
auth_router = APIRouter(
    dependencies=[Depends(get_current_user)]
)
class LoginRequest(BaseModel):
    name: str
    email: Optional[EmailStr] = None
    password: str

@user_router.post("/login")
def user_login(req: LoginRequest):
    return login_user(req.name, req.email, req.password)

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
@auth_router.get("/getCategoryByParentID/{parent_id}")
async def get_Category_By_ProductID(parent_id: int):
    return await get_all_category_by_parentID(parent_id)

# Get Categories with pageByLimit
@auth_router.get("/getCategoryPagesByLimit")
async def get_category_page_by_limit(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=500)):
    return await get_categories_pages(page, page_size)
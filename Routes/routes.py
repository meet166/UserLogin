from fastapi import APIRouter, Depends
from Controller.controller import login_user, get_current_user
from pydantic import BaseModel, EmailStr
from typing import Optional

user_router = APIRouter()
auth_router = APIRouter()

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
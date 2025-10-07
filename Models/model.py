from typing import Optional
from pydantic import BaseModel, EmailStr

class UserLogin(BaseModel):
    name: str
    email: Optional[EmailStr] = None
    password: str
    
class UserResponse(BaseModel):
    id: int
    name: str
    email: Optional[EmailStr] = None
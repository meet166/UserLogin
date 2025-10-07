from fastapi import FastAPI
from Routes import routes

from config import setupCors

app = FastAPI(title="User Login API")
setupCors(app)

app.include_router(routes.user_router, prefix="/user", tags=["User"])
app.include_router(routes.auth_router, prefix="/auth", tags=["Auth"])
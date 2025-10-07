from fastapi.middleware.cors import CORSMiddleware

origins = [
    "http://localhost:3306",
    "http://127.0.0.1:8000",
    "http://192.168.1.17:8000",
    "*"  # Allow all for testing
]

def setupCors(app):
    """
    Setup CORS middleware for FastAPI
    """
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
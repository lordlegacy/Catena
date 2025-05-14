from fastapi import FastAPI
from app.auth_routes import router as auth_router
from app.crypto_routes import router as crypto_router

app = FastAPI()

app.include_router(auth_router)
app.include_router(crypto_router)

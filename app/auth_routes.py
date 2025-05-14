from fastapi import APIRouter, HTTPException, Depends
from app.models import UserCreate
from app.db import get_user, add_user
from app.auth import hash_password, verify_password, create_access_token
from app.keys import generate_keys, encrypt_private_key
from fastapi.security import OAuth2PasswordRequestForm

router = APIRouter()

@router.post("/register")
def register(user: UserCreate):
    if get_user(user.username):
        raise HTTPException(status_code=400, detail="User already exists")
    private_key, public_key = generate_keys()
    encrypted_private = encrypt_private_key(private_key, user.password)
    add_user(user.username, hash_password(user.password), public_key.decode(), encrypted_private.decode())
    return {"msg": "User registered successfully"}

@router.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user[1]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": user[0]})
    return {"access_token": access_token, "token_type": "bearer"}

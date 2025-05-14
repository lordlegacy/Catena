from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Optional
import base64, os, sqlite3, datetime

# ==================== CONFIG ====================
SECRET_KEY = "ssupersecretkey"  # Change this
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ==================== DATABASE ====================
conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    hashed_password TEXT,
    public_key TEXT,
    encrypted_private_key TEXT
)
""")
conn.commit()

# ==================== FASTAPI ====================
app = FastAPI()


# ==================== MODELS ====================
class UserCreate(BaseModel):
    username: str
    password: str

class MessageRequest(BaseModel):
    recipient_username: str
    message: str

class DecryptRequest(BaseModel):
    encrypted_message: str
    password: str


# ==================== UTILS ====================
def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str):
    return pwd_context.verify(password, hashed)

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def encrypt_private_key(private_pem: bytes, password: str) -> bytes:
    password_bytes = password.encode()
    return serialization.load_pem_private_key(
        private_pem,
        password=None,
        backend=default_backend()
    ).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password_bytes)
    )

def decrypt_private_key(encrypted_pem: str, password: str):
    return serialization.load_pem_private_key(
        encrypted_pem.encode(),
        password=password.encode(),
        backend=default_backend()
    )

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + (expires_delta or datetime.timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(username: str):
    user = cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return user


# ==================== AUTH ====================
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials"
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise credentials_exception
        user = get_user(username)
        if not user:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception


# ==================== ROUTES ====================

@app.post("/register")
def register(user: UserCreate):
    if get_user(user.username):
        raise HTTPException(status_code=400, detail="User already exists")
    
    private_key, public_key = generate_keys()
    encrypted_private = encrypt_private_key(private_key, user.password)

    cursor.execute("INSERT INTO users VALUES (?, ?, ?, ?)", (
        user.username,
        hash_password(user.password),
        public_key.decode(),
        encrypted_private.decode()
    ))
    conn.commit()
    return {"msg": "User registered successfully"}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user[1]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": user[0]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/encrypt")
def encrypt_message(data: MessageRequest, current_user=Depends(get_current_user)):
    recipient = get_user(data.recipient_username)
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    public_key = serialization.load_pem_public_key(recipient[2].encode())
    encrypted = public_key.encrypt(
        data.message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )
    return {"encrypted_message": base64.b64encode(encrypted).decode()}

@app.post("/decrypt")
def decrypt_message(data: DecryptRequest, current_user=Depends(get_current_user)):
    encrypted_bytes = base64.b64decode(data.encrypted_message)
    try:
        private_key = decrypt_private_key(current_user[3], data.password)
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )
        return {"decrypted_message": decrypted.decode()}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Decryption failed: Invalid password or key")


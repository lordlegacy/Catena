from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    password: str

class MessageRequest(BaseModel):
    recipient_username: str
    message: str

class DecryptRequest(BaseModel):
    encrypted_message: str
    password: str

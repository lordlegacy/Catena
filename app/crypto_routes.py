from fastapi import APIRouter, Depends, HTTPException
from app.models import MessageRequest, DecryptRequest
from app.db import get_user
from app.auth import get_current_user
from app.keys import encrypt_message, decrypt_private_key, decrypt_message

router = APIRouter()

@router.post("/encrypt")
def encrypt_route(data: MessageRequest, current_user=Depends(get_current_user)):
    recipient = get_user(data.recipient_username)
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")
    encrypted = encrypt_message(recipient[2], data.message)
    return {"encrypted_message": encrypted}

@router.post("/decrypt")
def decrypt_route(data: DecryptRequest, current_user=Depends(get_current_user)):
    try:
        private_key = decrypt_private_key(current_user[3], data.password)
        message = decrypt_message(private_key, data.encrypted_message)
        return {"decrypted_message": message}
    except Exception:
        raise HTTPException(status_code=400, detail="Decryption failed: Invalid password or message")

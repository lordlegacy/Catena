# Catena
# 🔐 Secure Messaging API with FastAPI

A simple secure messaging backend built with **FastAPI**. This app allows users to register, authenticate, and securely send encrypted messages using RSA public-key cryptography.

---

## 🚀 Features

- User Registration & Login
- JWT Token Authentication
- Per-user RSA Keypair Generation
- Password-Protected Private Key Storage
- Public Key Encryption
- Secure Message Decryption
- SQLite Database for User Storage
- Auto-generated Swagger Docs

---

## 📦 Tech Stack

| Component             | Description                                           |
|-----------------------|-------------------------------------------------------|
| **FastAPI**           | High-performance Python web framework for APIs       |
| **SQLite**            | Lightweight relational database                      |
| **RSA (Cryptography)**| For public-key encryption/decryption                 |
| **JWT (`python-jose`)**| Secure token-based user authentication             |
| **Passlib (bcrypt)**  | Password hashing and verification                    |

---

## 🔧 How It Works

### ✅ 1. User Registration (`/register`)
- User submits `username` and `password`
- Password is hashed with bcrypt
- RSA keypair is generated per user
- Private key is encrypted using the user’s password
- Public key is stored in plain text
- Encrypted private key is stored in the database

### 🔐 2. User Login (`/login`)
- User submits their credentials
- If valid, a **JWT access token** is returned
- Token is used for protected requests

### ✉️ 3. Encrypt a Message (`/encrypt`)
- Authenticated user specifies:
  - `recipient_username`
  - `message`
- Server encrypts message using recipient’s public key
- Returns `encrypted_message` (base64 string)

### 🔓 4. Decrypt a Message (`/decrypt`)
- Authenticated user submits:
  - `encrypted_message`
  - `password`
- Server:
  - Decrypts private key using password
  - Uses private key to decrypt the message
- Returns the original message

---

## 📘 API Documentation

FastAPI provides interactive documentation:
- Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
- ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

## ✅ Example Routes

### `POST /register`
```json
{ "username": "alice", "password": "mypassword" }
```

### `POST /login`
**Form data:**
```
username=alice
password=mypassword
```

### `POST /encrypt`
```json
{
  "recipient_username": "bob",
  "message": "Hello Bob!"
}
```

### `POST /decrypt`
```json
{
  "encrypted_message": "base64_encrypted_text",
  "password": "mypassword"
}
```

---

## 📂 Future Ideas

- File encryption support
- Shared inbox or message store
- Expiring messages
- Frontend integration

---

Built for educational and prototyping purposes.


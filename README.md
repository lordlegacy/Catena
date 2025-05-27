# Catena  
🔐 Secure Messaging API with FastAPI

**Purpose of the Repository**  
Catena is a secure messaging backend built with FastAPI, designed with privacy and encryption at its core. It allows users to register, authenticate, and exchange encrypted messages using RSA public-key cryptography. The project is ideal for educational use and prototyping secure messaging systems.  


**Features and Technologies**  
- User registration and login  
- JWT token authentication  
- Per-user RSA keypair generation  
- Password-protected private key storage  
- Public key encryption and secure message decryption  
- SQLite database for user management  
- Auto-generated Swagger API documentation

**Tech Stack:**  
- **FastAPI:** High-performance Python web framework for APIs  
- **SQLite:** Lightweight relational database  
- **RSA (Cryptography):** Public-key encryption/decryption  
- **python-jose:** JWT token authentication  
- **Passlib (bcrypt):** Password hashing and verification

---

## 🚀 How to Use

Here’s a simple step-by-step illustration of using the Catena API:

1. **Register a User**  
   `POST /register`  
   ```json
   { "username": "alice", "password": "mypassword" }
   ```

2. **Login**  
   `POST /login` (form data)  
   ```
   username=alice
   password=mypassword
   ```
   - Receive a JWT access token.

3. **Encrypt a Message**  
   `POST /encrypt` (use your JWT token)  
   ```json
   {
     "recipient_username": "bob",
     "message": "Hello Bob!"
   }
   ```
   - Returns an encrypted message (base64 string).

4. **Decrypt a Message**  
   `POST /decrypt` (use your JWT token)  
   ```json
   {
     "encrypted_message": "base64_encrypted_text",
     "password": "mypassword"
   }
   ```
   - Returns the original (decrypted) message.

Explore interactive API docs at:  
- Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)  
- ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

**Built for educational and prototyping purposes.**

---

Let me know if you’d like to include more details or a diagram!

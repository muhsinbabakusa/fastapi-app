from fastapi import FastAPI, Depends, HTTPException, Form
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt

# Define constants for JWT token
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"

# OAuth2PasswordBearer to extract token from Authorization header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Dummy database of users with roles (Admin or User)
users_db = {
    "john_doe": {"password": "password123", "role": "user"},
    "admin_user": {"password": "adminpass", "role": "admin"},
    "muhsin": {"password": "ali", "role": "user"}
}

# Define the User login data (username, password)
class UserLogin(BaseModel):
    username: str
    password: str

# Define the User model with role and other necessary info
class User(BaseModel):
    username: str
    role: str

# Function to create a JWT token with user role and expiration time
def create_jwt_token(username: str, role: str):
    expiration_time = timedelta(hours=1)  # Token expires in 1 hour
    expiration_date = datetime.utcnow() + expiration_time
    payload = {"sub": username, "role": role, "exp": expiration_date}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

# Function to verify the JWT token and decode the payload
def verify_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Function to get the current user from the token (role included)
def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = verify_access_token(token)
    return User(username=payload["sub"], role=payload["role"])

# FastAPI app
app = FastAPI()

# Admin-only route
@app.get("/admin")
def admin_route(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Access forbidden: Admins only")
    return {"message": f"Hello {current_user.username}, you are an admin."}

# User route (accessible by both Admin and User)
@app.get("/user")
def user_route(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello {current_user.username}, you are a {current_user.role}."}

# Login route


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    user_data = users_db.get(username)
    if not user_data or user_data["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_jwt_token(username, user_data["role"])
    return {"access_token": token, "token_type": "bearer"}

# Refresh token route
@app.post("/refresh_token")
def refresh_token(current_user: User = Depends(get_current_user)):
    new_token = create_jwt_token(current_user.username, current_user.role)
    return {"access_token": new_token, "token_type": "bearer"}

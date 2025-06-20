from fastapi import FastAPI, HTTPException, Depends, Body, status, UploadFile, File, Query
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, create_engine, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from uuid import uuid4
import os
from email.mime.text import MIMEText
from smtplib import SMTP_SSL
from fastapi.staticfiles import StaticFiles
from typing import List, Optional
from fastapi.responses import JSONResponse
#slow requirementos 


SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_USER = "muhsinbabakusa@gmail.com"
SMTP_PASS =  "zmejyzjojcdsdkoe"
FROM_EMAIL = SMTP_USER




# Configuration
SECRET_KEY = "HDEYD3Y4RHVFDHMVETHV"
REFRESH_SECRET_KEY = "REFRESHSECRET123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 5
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./social_db2.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# FastAPI app
app = FastAPI()

#“Hey, if anyone visits /uploads/<filename>, go to the uploads/ folder on the server and serve that file.”
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

# CORS (for connecting frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace "*" with your frontend origin for security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def send_reset_email(to_email: str, reset_token: str):
    reset_link = f"https://your-domain.com/reset-password?token={reset_token}"
    subject = "Your Password Reset Link"
    body = f"Click this link to reset your password:\n\n{reset_link}\n\nIf you didn’t request this, ignore this email."

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email

    with SMTP_SSL(SMTP_HOST, SMTP_PORT) as smtp:
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.sendmail(FROM_EMAIL, [to_email], msg.as_string())

def send_verification_email(to_email: str, token: str):
    verification_link = f"http://localhost:8000/verify-email?token={token}"
    subject = "Verify Your Email"
    body = f"Click this link to verify your email:\n\n{verification_link}\n\nIf you didn’t register, ignore this email."

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email

    with SMTP_SSL(SMTP_HOST, SMTP_PORT) as smtp:
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.sendmail(FROM_EMAIL, [to_email], msg.as_string())

# Token creation
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, REFRESH_SECRET_KEY, algorithm=ALGORITHM)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Database models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    email = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(String, default="user")
    reset_token = Column(String, nullable=True)
    verification_token = Column(String, nullable=True)
    is_verified = Column(Boolean, default=False)
    profile_picture = Column(String, nullable=True) 
    is_active = Column(Boolean, default=True)  # <-- NEW FIELD

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)
    token = Column(String, unique=True, index=True)

Base.metadata.create_all(bind=engine)

# Pydantic schemas
class UserCreate(BaseModel):
    firstName: str
    lastName: str
    email: str
    username: str
    password: str
    role: str = "user"

class UserLogin(BaseModel):
    username: str
    password: str

class UserProfile(BaseModel):
    username: str
    firstname: str
    lastname: str
    email: str
    role: str
    profile_picture: str | None = None

    class Config:
        orm_mode = True
class UpdateUser(BaseModel):
    firstName : str = None
    lastName : str = None
    email : str = None
# Auth utils
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

def require_role(required_role: str):
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role != required_role:
            raise HTTPException(status_code=403, detail="Not authorized")
        return current_user
    return role_checker

# Routes

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_pw = get_password_hash(user.password)
    token = str(uuid4())
    
    db_user = User(
        first_name=user.firstName,
        last_name=user.lastName,
        email=user.email,
        username=user.username,
        password=hashed_pw,
        role=user.role,
        verification_token=token,
        is_verified=False
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    try:
        send_verification_email(user.email, token)
    except Exception as e:
        print("EMAIL ERROR:", e)
        raise HTTPException(status_code=500, detail="Failed to send verification email")

    return {"message": f"User {user.username} registered. Check your email to verify your account."}


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == form_data.username).first()
    if not db_user or not verify_password(form_data.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")
    access_token = create_access_token(data={"sub": db_user.username})
    refresh_token = create_refresh_token(data={"sub": db_user.username})

    db_refresh = RefreshToken(user_id=db_user.id, token=refresh_token)
    db.add(db_refresh)
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@app.post("/refresh")
def refresh_token(refresh_token: str = Body(...), db: Session = Depends(get_db)):
    stored_token = db.query(RefreshToken).filter(RefreshToken.token == refresh_token).first()
    if not stored_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    try:
        payload = jwt.decode(refresh_token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    new_access_token = create_access_token(data={"sub": username})
    return {"access_token": new_access_token, "token_type": "bearer"}

@app.get("/protected")
def protected_route(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello, {current_user.username}! You are authenticated."}

@app.get("/user-only")
def user_only_route(current_user: User = Depends(require_role("user"))):
    return {"message": f"Welcome, {current_user.username}. You have user access."}

@app.post("/request-password-reset")
def request_password_reset(email: str = Body(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    token = str(uuid4())
    user.reset_token = token
    db.commit()
    
    # Send the reset email
    try:
        send_reset_email(user.email, token)
    except Exception as e:
        print("EMAIL ERROR:", e)
        raise HTTPException(status_code=500, detail="Failed to send email")

    return {"message": "Password reset email sent"}



@app.post("/reset-password")
def reset_password(
    reset_token: str = Body(...),
    new_password: str = Body(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.reset_token == reset_token).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user.password = get_password_hash(new_password)
    user.reset_token = None
    db.commit()

    return {"message": "Password reset successful"}
@app.post("/upload")
def upload_file(file: UploadFile= File(...), current_user : User = Depends(get_current_user), db: Session = Depends(get_db)):
    upload_dir = "Images"
    os.makedirs(upload_dir, exist_ok=True)

    filename = f"{current_user.username}_{file.filename}"
    file_path = os.path.join(upload_dir, filename)

     
    with open(file_path, "wb") as f:
        f.write(file.file.read())

    current_user.profile_picture = f"/uploads/{filename}"
    db.commit()
     

    return {"message": "Profile picture uploaded", "url": f"/uploads/{filename}"}
  
@app.get("/profile", response_model=UserProfile)
def get_profile(current_user: User = Depends(get_current_user),):
    return current_user


@app.put("/profile_update")
def update_profile(
    updates: UpdateUser,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    email_changed = False

    if updates.firstName:
        current_user.first_name = updates.firstName
    if updates.lastName:
        current_user.last_name = updates.lastName
    if updates.email and updates.email != current_user.email:
        current_user.email = updates.email
        current_user.is_verified = False  # Invalidate previous verification
        current_user.verification_token = str(uuid4())  # New token
        email_changed = True

    db.commit()
    db.refresh(current_user)

    if email_changed:
        try:
            send_verification_email(current_user.email, current_user.verification_token)
        except Exception as e:
            print("EMAIL ERROR:", e)
            return JSONResponse(status_code=500, content={"detail": "Profile updated but failed to send verification email"})

    return {
        "message": "Profile updated successfully",
        "profile": {
            "firstName": current_user.first_name,
            "lastName": current_user.last_name,
            "email": current_user.email,
            "username": current_user.username,
            "verified": current_user.is_verified
        }
    }
@app.put("/change_password")
def change_password(current_password: str = Body(...), new_password: str = Body(...), current_user: User=Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(current_password, current_user.password):
        raise HTTPException(status_code= 400, detail="incorect password")
    
    hashed_new_password = get_password_hash(new_password)

    current_user.password = hashed_new_password
    db.commit()
    
    return {"message": "Password chnaged succesfully"}

@app.get("/all-users")
def get_all_users(
    skip: int = 0,
    limit: int = 10,
    db: Session = Depends(get_db)
):
    total_users = db.query(User).count()
    users = db.query(User).offset(skip).limit(limit).all()

    return {
        "total_users": total_users,
        "page_size": len(users),
        "users": [
            {
                "id": user.id,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "username": user.username,
                "role": user.role
            }
            for user in users
        ]
    }

@app.get("/users/search")
def search_users(
    username: Optional[str] = None,
    email: Optional[str] = None,
    role: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1),
    db: Session = Depends(get_db)
):
    query = db.query(User).filter(User.is_active == True)

    if username:
        query = query.filter(User.username.ilike(f"%{username}%"))
    if email:
        query = query.filter(User.email.ilike(f"%{email}%"))
    if role:
        query = query.filter(User.role == role)

    total = query.count()  # Count total results matching filters
    users = query.offset(skip).limit(limit).all()

    
    return {
        "total": total,
        "results": [
            {
                "id": user.id,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "username": user.username,
                "role": user.role
            } for user in users
        ]
    }
@app.put("/deactivate_user")
def deactivate_user(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role("admin"))):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.is_active = False
    db.commit()
    db.refresh(user)

    return{
        "message": f"{user.username} is deactivated"
    }
@app.put("/activate_user")
def activate_user(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role("admin"))):
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.is_active:
        user.is_active = True
        db.commit()
        db.refresh(user)
        return {"message": f"User {user.username} has been activated"}
    
    return {"message": f"User {user.username} is already active"}
@app.get("/users/active")
def active_users(db: Session = Depends(get_db)):
    users = db.query(User).filter(User.is_active == True).all()
    return{
        "active_users":[
            user.username
            for user in users
        ]
    }
@app.get("/users/in-active")
def in_active_users(db: Session = Depends(get_db)):
    users = db.query(User).filter(User.is_active == False).all()
    return{
        "active_users":[
            user.username
            for user in users
        ]
    }
@app.post("/logout")
def logout(refresh_token: str = Body(...), db: Session = Depends(get_db)):
    token_entry = db.query(RefreshToken).filter(RefreshToken.token == refresh_token).first()
    if not token_entry:
        raise HTTPException(status_code=404, detail="Token not found")
    
    db.delete(token_entry)
    db.commit()
    return {"message": "Logged out and token revoked"}

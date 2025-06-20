from fastapi import FastAPI, HTTPException,Depends, Body, status, UploadFile, File, Query, Request
from fastapi import BackgroundTasks
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
import inspect
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import redis  # new
import json
from dotenv import load_dotenv
import os

load_dotenv()




#token
SECRET_KEY = os.getenv("SECRET_KEY")
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10
ACCESS_TOKEN_EXPIRE_DAYS = 7

#nan ne Database
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()


#email utilitiress
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
FROM_EMAIL = SMTP_USER

#roles for access limit
role_limit= {
    "user" : "5/minutes",
    "premium" : "20/minutes",
    "admin": "100/minutes"
}

#tables hhhh
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    username = Column(String)
    email = Column(String)
    password = Column(String)
    role = Column(String)
    role = Column(String, default="user")
    reset_token = Column(String, nullable=True)
    verification_token = Column(String, nullable=True)
    is_verified = Column(Boolean, default=False)
    profile_picture = Column(String, nullable=True) 
    is_active = Column(Boolean, default=True) 

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)
    token = Column(String, unique=True, index=True)

#db execution
Base.metadata.create_all(bind=engine)

role_levels = {
    "user": 1,
    "premium": 2,
    "admin": 3,
}


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

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

def reset_success_email(to_email: str):
    reset_link = f"https://your-domain.com/reset-password?token"
    subject = "Your Password Reset Link"
    body = f"Your password has been reset succesfully, Thank u for using our product"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email

    with SMTP_SSL(SMTP_HOST, SMTP_PORT) as smtp:
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.sendmail(FROM_EMAIL, [to_email], msg.as_string())        

def send_verification_email(to_email: str, token: str):
    try:
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

        print("✅ Email sent successfully to", to_email)

    except Exception as e:
        print("❌ EMAIL ERROR:", e)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days= ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, REFRESH_SECRET_KEY, algorithm= ALGORITHM)

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

def get_user_role_key(request: Request):
    auth_header = request.headers.get("Authorization")#this extract authorization header from the http request
    ip = get_remote_address(request)#this gets the ip address
    
    if not auth_header or not auth_header.startswith("Bearer "):
        return f"Anonymous : {ip}"
    
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        role = payload.get("role", "free")
    except JWTError:
        role = "free"
    
    return f"{role}:{ip}"

def require_min_role(required_role: str):
    def role_dependency(user: User = Depends(get_current_user)):
        user_level = role_levels.get(user.role, 0)
        required_level = role_levels.get(required_role, 0)

        if user_level < required_level:
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        return user  # 🧠 You can still use this user in the route
    return role_dependency

class UserCreate(BaseModel):
    firstName: str
    lastName: str
    email: str
    username: str
    password: str
    role: str = "user"

class UserProfile(BaseModel):
    username: str
    first_name: str
    last_name: str
    email: str
    role: str
    profile_picture: str | None = None


    class Config:
        orm_mode = True     

class UpdateUser(BaseModel):
    firstName : str = None
    lastName : str = None
    email : str = None

class UpdateRole(BaseModel):
    role : str = None
 
class Login(BaseModel):
    username: str
    password: str

class VerifyEmail(BaseModel):
    email: str

app = FastAPI()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
#REDIS CONNECTION
redis_client = redis.Redis(
    host="localhost",      # Redis is running locally
    port=6379,             # default Redis port
    db=0,                  # default Redis database
    decode_responses=True  )


@app.post("/create_users")
def create_user(
    background_tasks: BackgroundTasks,
    user: UserCreate,
    db: Session = Depends(get_db)
):
    existing = db.query(User).filter(User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    

    hashed_password = get_password_hash(user.password)
    new_user = User(
        first_name=user.firstName,
        last_name=user.lastName,
        username=user.username,
        email=user.email,
        password=hashed_password,
        role=user.role,
        is_verified=False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    #deleting of refreshing cache
    redis_client.delete("all_users_skip0_limit10")

    token = str(uuid4())
    background_tasks.add_task(send_verification_email, user.email, token)

    return {
        "message": f"{user.firstName} registered successfully",
        "data": user
    }

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == form_data.username).first()
    if not db_user or not verify_password(form_data.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")
    access_token = create_access_token(data={"sub": db_user.username})
    refresh_token = create_refresh_access_token(data={"sub": db_user.username})

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


@app.post("/verify-email")
def verify_email(
    email: str = Body(...),
    username: str = Body(...),
    db: Session = Depends(get_db)
):
    token = str(uuid4())
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email")

    try:
        send_verification_email(user.email, token)
    except Exception as e:
        print("EMAIL ERROR:", e)
        raise HTTPException(status_code=500, detail="Failed to send verification email")

    return {
        "message":f"{user.username}'s email verified'",
        
}

@app.post("/request-password-reset")
def request_password_reset(email: str = Body(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=403, detail="invalid-EMAIL")

    token = str(uuid4())
    user.reset_token = token
    db.commit()
    
    

    try:
        send_reset_email(user.email, token)
    except Exception as e:
        print("EMAIL ERROR:", e)
        raise HTTPException(status_code=500, detail="Failed to send email")

    return {"message": "Password reset email sent",
            "code": token
            }

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

@app.put("/change-password")
def change_password(current_password: str = Body(...), new_password: str = Body(...),db:Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not verify_password(current_password, User.password):
        raise HTTPException(status_code = 400, detail="password does not match")
    
    new_hash = get_password_hash(new_password)
    User.password = new_hash
    db.commit()

    return{"measage": "success"}


#user's route
@app.get("/profile", response_model=UserProfile)
def profile(current_user : User = Depends(get_current_user)):
    cache_key = f"profle: {current_user.username}"
    cached_data = redis_client.get(cache_key)
    if cached_data:
        return json.loads(cached_data)
    result = {
        "username": current_user.username,
        "first_name": current_user.first_name,
        "last_name": current_user.last_name,
        "email": current_user.email,
        "role": current_user.role,
        "profile_picture": current_user.profile_picture
    }
    redis_client.set(cache_key, json.dumps(result), ex=60)
    return result

@app.put("/update-profile")
def update_profile(update: UpdateUser, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    email_change = False

    if update.firstName:
        current_user.first_name = update.firstName
    if update.lastName:
        current_user.last_name = update.lastName
    if update.email and update.email != current_user.email:
        current_user.email = update.email
        current_user.is_verified = False
        current_user.verification_token = str(uuid4())
        email_change = True

    db.commit()
    db.refresh(current_user)

    # 🧹 Invalidate profile cache
    cache_key = f"profile:{current_user.username}"
    redis_client.delete(cache_key)

    if email_change:
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


@app.post("/profile_picture")
def profile_picture(file: UploadFile =File(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    upload_dir = "Profile_pictures"

    os.makedirs(upload_dir, exist_ok=True)

    filename = f"{current_user.username}_{file.filename}"
    file_path = os.path.join(upload_dir, filename)

     
    with open(file_path, "wb") as f:
        f.write(file.file.read())

    current_user.profile_picture = f"/uploads/{filename}"
    db.commit()   

    return {"message": "Profile picture uploaded successfully"} 

#admin routes
limiter = Limiter(key_func=get_user_role_key)
@app.get("/all-users")
def get_all_users(
    skip: int = 0,
    limit: int = 10,
    db: Session = Depends(get_db)
):
    # 🔑 Key to identify this result in Redis
    cache_key = f"all_users_skip{skip}_limit{limit}"

    # 🧠 Check if result is already cached in Redis
    cached_data = redis_client.get(cache_key)
    
    if cached_data:
        # 💡 If cache exists, return the result instantly from Redis
        return json.loads(cached_data)

    # ❌ No cache → Fetch from database
    total_users = db.query(User).count()
    users = db.query(User).offset(skip).limit(limit).all()

    # 🎁 Format the response to return
    response_data = {
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

    # 💾 Save response in Redis for 60 seconds
    redis_client.set(cache_key, json.dumps(response_data), ex=60)

    # 📤 Return the actual response
    return response_data
@app.put("/deactivate-user")
def activate_user(id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role("admin"))):
    user = db.query(User).filter(User.id == id).first()
    if not user:
        raise HTTPException(status_code=400, detail="user not found")
    user.is_active = False
    db.commit()
    db.refresh(user)
        #deleting of refreshing cache
    redis_client.delete("all_users_skip0_limit10")
    return {"message": f"{user.username} is deactivated"}

@app.put("/activate-user")
def deactivate_user(id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role("admin"))):
    user = db.query(User).filter(User.id == id).first()
    if not user:
        raise HTTPException(status_code=400, detail="user not found")
    if user.is_active == False:
        user.is_active = True
    else:
        raise HTTPException(status_code=400, detail="the user is already deactivated")    

    db.commit()
    db.refresh(user)
        #deleting of refreshing cache
    redis_client.delete("all_users_skip0_limit10")
    return {"message": f"{user.username} is activated"}

@app.put("/update_role")
def update_role(id: int, role: UpdateRole, db: Session = Depends(get_db), current_user: User = Depends(require_role("admin"))):
    user= db.query(User).filter(User.id == id).first()

    if not user:
        raise HTTPException(status_code=404, detail="user not found")
    
    user.role = role.role
    db.commit()
    db.refresh(user)
        #deleting of refreshing cache
    redis_client.delete("all_users_skip0_limit10")
    return{"message": "role changed"}

@app.get("/limited")
@limiter.limit("10/minute")  # ⛔ max 5 requests per minute
def limited_access(request: Request):
    return {"message": "You’re not blocked!"}


@app.post("/limitation")
@limiter.limit("5/hour")
def muhsin(request: Request, db: Session = Depends(get_db)):
    return    

@app.get("/admin-zone")
def admin_only(user: User = Depends(require_min_role("admin"))):
    return {"message": f"Welcome Admin {user.username}"}

@app.get("/premium-content")
def premium(user: User = Depends(require_min_role("premium"))):
    return {"message": f"Welcome Premium User {user.username}"}


@app.get("/dashboard")
@limiter.limit(lambda request: role_limit.get(
    jwt.decode(
        request.headers.get("Authorization", "").replace("Bearer ", ""),
        SECRET_KEY,
        algorithms=[ALGORITHM]
    ).get("role", "user"), "5/minute"))
def dashboard(request: Request):
    return {"message": "📊 Welcome to the dashboard!"}
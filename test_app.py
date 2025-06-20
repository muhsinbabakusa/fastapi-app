from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel

app = FastAPI()

class User(BaseModel):
    username: str
    email: str

def send_email(email: str):
    print(f"📨 Email sent to {email}")

@app.post("/register")
def register_user(user: User, background_tasks: BackgroundTasks):  # ✅ This must work
    background_tasks.add_task(send_email, user.email)
    return {"message": "User registered"}

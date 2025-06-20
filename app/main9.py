from fastapi import FastAPI
from dotenv import load_dotenv
import os

load_dotenv()  # 🔥 Load .env file into environment

app = FastAPI()

@app.get("/")
def root():
    return {
        "app": os.getenv("APP_NAME"),
        "env": os.getenv("ENVIRONMENT")
    }

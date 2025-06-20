from fastapi import FastAPI, UploadFile, HTTPException, status, File
import os

app = FastAPI()

@app.post("/file")
def upload_file(file: UploadFile = File(...)):
    upload_dir = "uploads"
    os.makedirs(upload_dir, exist_ok=True)  # Create folder if it doesn't exist

    file_path = os.path.join(upload_dir, file.filename)

    with open(file_path, "wb") as f:
        f.write(file.file.read())

    return {"message": "File uploaded", "path": file_path}
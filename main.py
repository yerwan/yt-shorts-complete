
import os
import subprocess
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from sqlite3 import connect

app = FastAPI()

SECRET_KEY = "your_real_secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

conn = connect("users.db")
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)")
conn.commit()

class User(BaseModel):
    username: str
    password: str

class VideoRequest(BaseModel):
    youtube_url: str

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def decode_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/signup")
def signup(user: User):
    hashed = get_password_hash(user.password)
    try:
        cursor.execute("INSERT INTO users VALUES (?, ?)", (user.username, hashed))
        conn.commit()
        return {"message": "Signup successful"}
    except:
        raise HTTPException(status_code=400, detail="Username already exists")

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    cursor.execute("SELECT password FROM users WHERE username = ?", (form_data.username,))
    user = cursor.fetchone()
    if not user or not verify_password(form_data.password, user[0]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_access_token(data={"sub": form_data.username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/generate")
def generate_shorts(request: VideoRequest, user: str = Depends(decode_token)):
    url = request.youtube_url

    # Download video using yt-dlp
    output_file = "downloaded.mp4"
    try:
        subprocess.run(["yt-dlp", "-o", output_file, url], check=True)
    except:
        raise HTTPException(status_code=500, detail="Video download failed")

    # Transcribe using whisper
    try:
        transcript = subprocess.check_output(["whisper", output_file, "--model", "base", "--output_format", "txt"])
    except:
        transcript = b"Transcription failed"

    # Return mock clips (you can add ffmpeg/moviepy logic to trim if needed)
    return {
        "shorts": ["https://yourdomain.com/clip1.mp4", "https://yourdomain.com/clip2.mp4"],
        "transcript": transcript.decode("utf-8")[:1000],
        "virality_score": "72%",
        "preview": "https://yourdomain.com/preview.mp4"
    }

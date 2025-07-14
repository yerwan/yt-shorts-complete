
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import List
from datetime import datetime, timedelta
from sqlite3 import connect

app = FastAPI()

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# DB setup
conn = connect("users.db")
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)")
conn.commit()

# Models
class User(BaseModel):
    username: str
    password: str

class VideoInput(BaseModel):
    youtube_url: str

# Auth
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

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
        return {"msg": "User registered"}
    except:
        raise HTTPException(status_code=400, detail="Username already exists")

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    cursor.execute("SELECT password FROM users WHERE username = ?", (form_data.username,))
    result = cursor.fetchone()
    if not result or not verify_password(form_data.password, result[0]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_access_token(data={"sub": form_data.username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/generate")
def generate(data: VideoInput, user: str = Depends(decode_token)):
    return {
        "status": "success",
        "message": f"Video from {data.youtube_url} processed",
        "shorts": [
            "https://example.com/short1.mp4",
            "https://example.com/short2.mp4"
        ],
        "virality_score": "78%",
        "transcript": "Full transcript here...",
        "preview_link": "https://example.com/preview.mp4"
    }

@app.get("/protected")
def protected_route(user: str = Depends(decode_token)):
    return {"message": f"Hello {user}, you are authenticated!"}

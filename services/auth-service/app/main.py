# main.py
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
from fastapi.security import OAuth2PasswordBearer

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Example in-memory user database
fake_users_db = {
    "user1": {
        "username": "user1",
        "full_name": "User One",
        "email": "user1@example.com",
        "hashed_password": "fakehashedpassword",
        "disabled": False,
    }
}

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

def fake_hash_password(password: str):
    return "fakehashed" + password

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def fake_decode_token(token):
    user = get_user(fake_users_db, token)
    return user

@app.post("/token")
async def login(form_data: dict):
    username = form_data.get("username")
    password = form_data.get("password")
    user = get_user(fake_users_db, username)
    if not user or fake_hash_password(password) != user.hashed_password:
        raise HTTPException(status_code=400, detail="Invalid username or password")
    return {"access_token": username, "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    user = fake_decode_token(token)
    if user is None or user.disabled:
        raise HTTPException(status_code=400, detail="Invalid user")
    return user

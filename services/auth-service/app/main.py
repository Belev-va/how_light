# main.py
from fastapi import FastAPI, HTTPException, Depends, Form
from pydantic import BaseModel
from typing import Optional
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Database setup
DATABASE_URL = "mysql+pymysql://auth_user:auth_password@db/auth_db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    full_name = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    disabled = Column(Boolean, default=False)

# Create tables
Base.metadata.create_all(bind=engine)

# Pydantic models
class UserCreate(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None
    password: str

class UserResponse(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

# Utility functions
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user_by_username(db, username: str):
    return db.query(User).filter(User.username == username).first()

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate, db: SessionLocal = Depends(get_db)):
    db_user = get_user_by_username(db, user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = hash_password(user.password)
    new_user = User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=hashed_password
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/token")
async def login(username: str = Form(...), password: str = Form(...), db: SessionLocal = Depends(get_db)):
    user = get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    return {"access_token": username, "token_type": "bearer"}

@app.get("/users/me", response_model=UserResponse)
def read_users_me(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    user = get_user_by_username(db, token)
    if not user or user.disabled:
        raise HTTPException(status_code=400, detail="Invalid user")
    return user

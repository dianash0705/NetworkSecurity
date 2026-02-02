from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, String, Integer, Boolean, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from datetime import datetime
from typing import List

# --- Database Setup ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./teetime_backend.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    username = Column(String, primary_key=True, index=True)
    public_key = Column(String, nullable=False)

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String, ForeignKey("users.username"))
    receiver = Column(String, ForeignKey("users.username"))
    encrypted_content = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_delivered = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

# --- Pydantic Schemas ---
class UserResponse(BaseModel):
    username: str
    public_key: str
    class Config:
        from_attributes = True

class MessageResponse(BaseModel):
    id: int
    sender: str
    receiver: str
    encrypted_content: str
    timestamp: datetime
    is_delivered: bool
    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    username: str
    public_key: str

class MessageSend(BaseModel):
    sender: str
    receiver: str
    encrypted_content: str

app = FastAPI(title="TeeTime E2EE Backend")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Existing Endpoints ---

@app.post("/register", tags=["User Actions"])
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        db_user.public_key = user.public_key
    else:
        db_user = User(username=user.username, public_key=user.public_key)
        db.add(db_user)
    db.commit()
    return {"status": "success"}

@app.post("/send-message", tags=["Message Actions"])
def send_message(msg: MessageSend, db: Session = Depends(get_db)):
    new_msg = Message(sender=msg.sender, receiver=msg.receiver, encrypted_content=msg.encrypted_content)
    db.add(new_msg)
    db.commit()
    return {"status": "Message queued"}

# --- New "Admin View" Endpoints for Swagger ---

@app.get("/users", response_model=List[UserResponse], tags=["Admin View"])
def get_all_users(db: Session = Depends(get_db)):
    """Retrieve the full list of registered TeeTime users and their public keys."""
    return db.query(User).all()

@app.get("/all-messages", response_model=List[MessageResponse], tags=["Admin View"])
def get_all_messages(db: Session = Depends(get_db)):
    """Retrieve every message stored in the database (Admin Debug Mode)."""
    return db.query(Message).all()
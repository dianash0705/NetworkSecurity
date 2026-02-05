from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, String, Integer, Boolean, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from datetime import datetime
from typing import List

# --- Database Setup ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./teatime_backend.db"
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

# --- Pydantic Schemas (Data Validation) ---
class UserCreate(BaseModel):
    username: str
    public_key: str

class MessageSend(BaseModel):
    sender: str
    receiver: str
    encrypted_content: str

# New Schemas for Admin Views
class UserOut(BaseModel):
    username: str
    public_key: str
    class Config:
        from_attributes = True

class MessageOut(BaseModel):
    id: int
    sender: str
    receiver: str
    encrypted_content: str
    timestamp: datetime
    is_delivered: bool
    class Config:
        from_attributes = True

app = FastAPI(title="E2E TeaTime Backend")

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- User API Endpoints ---

@app.post("/register", tags=["User Actions"])
def register(user: UserCreate, db: Session = Depends(get_db)):
    """Users register their Public Key here."""
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        db_user.public_key = user.public_key
    else:
        db_user = User(username=user.username, public_key=user.public_key)
        db.add(db_user)
    db.commit()
    return {"status": "success"}

@app.get("/get-public-key/{username}", tags=["User Actions"])
def get_key(username: str, db: Session = Depends(get_db)):
    """Clients call this to get the key needed to encrypt a message for 'username'."""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"username": username, "public_key": user.public_key}

@app.post("/send-message", tags=["User Actions"])
def send_message(msg: MessageSend, db: Session = Depends(get_db)):
    """Receives an already encrypted blob and stores it for the receiver."""
    receiver = db.query(User).filter(User.username == msg.receiver).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")
    
    new_msg = Message(
        sender=msg.sender,
        receiver=msg.receiver,
        encrypted_content=msg.encrypted_content
    )
    db.add(new_msg)
    db.commit()
    return {"status": "Message queued for delivery"}

@app.get("/fetch-messages/{username}", tags=["User Actions"])
def fetch_messages(username: str, db: Session = Depends(get_db)):
    """Receiver calls this to get their new encrypted messages."""
    messages = db.query(Message).filter(
        Message.receiver == username, 
        Message.is_delivered == False
    ).all()
    
    for m in messages:
        m.is_delivered = True
    db.commit()
    
    return messages

# --- Admin API Endpoints (New) ---

@app.get("/admin/users", response_model=List[UserOut], tags=["Admin View"])
def list_all_users(db: Session = Depends(get_db)):
    """See all registered users and their public keys."""
    return db.query(User).all()

@app.get("/admin/messages", response_model=List[MessageOut], tags=["Admin View"])
def list_all_messages(db: Session = Depends(get_db)):
    """See every message in the database, regardless of delivery status."""
    return db.query(Message).all()
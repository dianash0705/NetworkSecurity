from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, String, Integer, Boolean, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from datetime import datetime
from typing import List
from contextlib import asynccontextmanager
from apscheduler.schedulers.background import BackgroundScheduler

# --- Database Setup ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./teatime_backend.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    username = Column(String, primary_key=True, index=True)
    public_key = Column(String, nullable=False)
    identity_key_public = Column(String, nullable=False)
    prekey_public = Column(String, nullable=True)
    prekey_signature_public = Column(String, nullable=True)
    prekey_needs_update = Column(Boolean, default=False)  # Flag to signal client to update prekeys

class OneTimeKey(Base):
    __tablename__ = "onetime_keys"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, ForeignKey("users.username"), nullable=False)
    onetime_key_public = Column(String, nullable=False)
    is_used = Column(Boolean, default=False)

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

class UserRegister(BaseModel):
    username: str
    public_key: str
    identity_key_public: str
    prekey_public: str
    prekey_signature_public: str
    onetime_keys_public: List[str]  # Client should send ~10 onetime public keys

class OneTimeKeyUpload(BaseModel):
    username: str
    onetime_keys_public: List[str]

class PrekeyUpdate(BaseModel):
    username: str
    prekey_public: str
    prekey_signature_public: str

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

class OneTimeKeyOut(BaseModel):
    id: int
    username: str
    onetime_key_public: str
    is_used: bool
    class Config:
        from_attributes = True

class KeyBundleOut(BaseModel):
    username: str
    identity_key_public: str
    prekey_public: str
    prekey_signature_public: str
    onetime_key_public: str | None  # One onetime public key for the session

ONETIME_KEY_THRESHOLD = 2  # When user has this many keys left, request more
PREKEY_ROTATION_INTERVAL_WEEKS = 1  # Rotate prekeys every week

# --- Scheduler Setup ---
scheduler = BackgroundScheduler()

def flag_all_users_for_prekey_update():
    """
    Periodic task that runs weekly to flag all users to update their prekeys.
    Sets prekey_needs_update=True for all users.
    """
    db = SessionLocal()
    try:
        db.query(User).update({User.prekey_needs_update: True})
        db.commit()
        print(f"[{datetime.utcnow()}] Flagged all users for prekey update")
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start the scheduler
    scheduler.add_job(
        flag_all_users_for_prekey_update,
        'interval',
        weeks=PREKEY_ROTATION_INTERVAL_WEEKS,
        id='prekey_rotation_job',
        name='Weekly Prekey Rotation Flag'
    )
    scheduler.start()
    print(f"[{datetime.utcnow()}] Scheduler started - prekey rotation every {PREKEY_ROTATION_INTERVAL_WEEKS} week(s)")
    yield
    # Shutdown: Stop the scheduler
    scheduler.shutdown()
    print(f"[{datetime.utcnow()}] Scheduler stopped")

app = FastAPI(title="E2E TeaTime Backend", lifespan=lifespan)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Helper Functions ---

def get_onetime_keys_status(username: str, db: Session) -> dict:
    """
    Helper function to check onetime keys status for a user.
    Returns remaining keys count and whether more keys are needed.
    """
    remaining_keys = db.query(OneTimeKey).filter(
        OneTimeKey.username == username,
        OneTimeKey.is_used == False
    ).count()
    
    return {
        "remaining_onetime_keys": remaining_keys,
        "needs_more_keys": remaining_keys <= ONETIME_KEY_THRESHOLD
    }

# --- User API Endpoints ---

@app.post("/register", tags=["User Actions"])
def register(user: UserRegister, db: Session = Depends(get_db)):
    """
    Register a new user with X3DH key bundle.
    Client must provide:
    - identity_key_public
    - prekey_public
    - prekey_signature_public
    - onetime_keys_public (list of ~10 public keys)
    """
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        # Update existing user's keys
        db_user.public_key = user.public_key
        db_user.identity_key_public = user.identity_key_public
        db_user.prekey_public = user.prekey_public
        db_user.prekey_signature_public = user.prekey_signature_public
        # Delete old unused onetime keys and add new ones
        db.query(OneTimeKey).filter(
            OneTimeKey.username == user.username,
            OneTimeKey.is_used == False
        ).delete()
    else:
        db_user = User(
            username=user.username,
            public_key=user.public_key,
            identity_key_public=user.identity_key_public,
            prekey_public=user.prekey_public,
            prekey_signature_public=user.prekey_signature_public
        )
        db.add(db_user)
    
    # Add onetime public keys to the separate table
    for key in user.onetime_keys_public:
        onetime_key = OneTimeKey(username=user.username, onetime_key_public=key)
        db.add(onetime_key)
    
    db.commit()
    return {"status": "success", "onetime_keys_public_stored": len(user.onetime_keys_public)}

@app.post("/upload-onetime-keys", tags=["User Actions"])
def upload_onetime_keys(data: OneTimeKeyUpload, db: Session = Depends(get_db)):
    """
    Upload additional onetime public keys when running low.
    Called by client when server indicates keys are running low.
    """
    user = db.query(User).filter(User.username == data.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    for key in data.onetime_keys_public:
        onetime_key = OneTimeKey(username=data.username, onetime_key_public=key)
        db.add(onetime_key)
    
    db.commit()
    
    keys_status = get_onetime_keys_status(data.username, db)
    
    return {"status": "success", "onetime_keys_public_added": len(data.onetime_keys_public), "total_available": keys_status["remaining_onetime_keys"]}

@app.post("/update-prekeys", tags=["User Actions"])
def update_prekeys(data: PrekeyUpdate, db: Session = Depends(get_db)):
    """
    Update user's prekey and prekey signature.
    Called by client when server flags that prekeys need rotation.
    """
    user = db.query(User).filter(User.username == data.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.prekey_public = data.prekey_public
    user.prekey_signature_public = data.prekey_signature_public
    user.prekey_needs_update = False  # Clear the update flag
    
    db.commit()
    return {"status": "success", "message": "Prekeys updated successfully"}

@app.get("/check-prekey-status/{username}", tags=["User Actions"])
def check_prekey_status(username: str, db: Session = Depends(get_db)):
    """
    Check if a user needs to update their prekeys.
    Client should call this periodically to check for required key rotation.
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "username": username,
        "prekey_needs_update": user.prekey_needs_update
    }

@app.get("/get-key-bundle/{username}", tags=["User Actions"])
def get_key_bundle(username: str, db: Session = Depends(get_db)):
    """
    Get the full X3DH key bundle for a user (used to initiate a session).
    This consumes one onetime key from the user's pool.
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get an unused onetime key
    onetime_key_record = db.query(OneTimeKey).filter(
        OneTimeKey.username == username,
        OneTimeKey.is_used == False
    ).first()
    
    onetime_key_public_value = None
    if onetime_key_record:
        onetime_key_public_value = onetime_key_record.onetime_key_public
        onetime_key_record.is_used = True
        db.commit()
    
    # Check remaining onetime keys and warn if low
    keys_status = get_onetime_keys_status(username, db)
    
    return {
        "username": username,
        "identity_key_public": user.identity_key_public,
        "prekey_public": user.prekey_public,
        "prekey_signature_public": user.prekey_signature_public,
        "onetime_key_public": onetime_key_public_value,
        **keys_status
    }

@app.get("/get-prekey-bundle/{username}", tags=["User Actions"])
def get_prekey_bundle(username: str, db: Session = Depends(get_db)):
    """
    Get the prekey bundle for a user to start a new conversation.
    Returns:
    - identity_key_public
    - prekey_public
    - prekey_signature_public
    - onetime_key_public (deleted from server after retrieval)
    
    The onetime key is permanently deleted after being returned.
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get an unused onetime key
    onetime_key_record = db.query(OneTimeKey).filter(
        OneTimeKey.username == username,
        OneTimeKey.is_used == False
    ).first()
    
    onetime_key_public_value = None
    if onetime_key_record:
        onetime_key_public_value = onetime_key_record.onetime_key_public
        # Delete the onetime key after retrieval
        db.delete(onetime_key_record)
        db.commit()
    
    # Check remaining onetime keys and warn if low
    keys_status = get_onetime_keys_status(username, db)
    
    return {
        "username": username,
        "identity_key_public": user.identity_key_public,
        "prekey_public": user.prekey_public,
        "prekey_signature_public": user.prekey_signature_public,
        "onetime_key_public": onetime_key_public_value,
        **keys_status
    }

@app.get("/check-onetime-keys/{username}", tags=["User Actions"])
def check_onetime_keys(username: str, db: Session = Depends(get_db)):
    """
    Check how many onetime keys a user has left.
    Returns whether the client should generate more keys.
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    keys_status = get_onetime_keys_status(username, db)
    
    return {
        "username": username,
        **keys_status,
        "threshold": ONETIME_KEY_THRESHOLD
    }

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

@app.get("/admin/onetime-keys", response_model=List[OneTimeKeyOut], tags=["Admin View"])
def list_all_onetime_keys(db: Session = Depends(get_db)):
    """See all onetime keys in the database."""
    return db.query(OneTimeKey).all()

@app.get("/admin/onetime-keys/{username}", tags=["Admin View"])
def list_user_onetime_keys(username: str, db: Session = Depends(get_db)):
    """See onetime keys for a specific user with usage statistics."""
    keys = db.query(OneTimeKey).filter(OneTimeKey.username == username).all()
    used_count = sum(1 for k in keys if k.is_used)
    available_count = len(keys) - used_count
    
    return {
        "username": username,
        "total_keys": len(keys),
        "used_keys": used_count,
        "available_keys": available_count,
        "needs_more_keys": available_count <= ONETIME_KEY_THRESHOLD,
        "keys": keys
    }
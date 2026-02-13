from contextlib import asynccontextmanager
from datetime import datetime
from typing import List, Dict

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Integer, Boolean, DateTime, ForeignKey, or_, and_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session


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
    prekey_public = Column(String, nullable=False)
    prekey_signature_public = Column(String, nullable=False)
    signing_key_public = Column(String, nullable=True)
    prekey_needs_update = Column(Boolean, default=False)  # Flag to signal client to update prekeys


class OneTimeKey(Base):
    __tablename__ = "onetime_keys"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, ForeignKey("users.username"), nullable=False)
    onetime_key_public = Column(String, nullable=False)
    is_used = Column(Boolean, default=False)


class Friendship(Base):
    __tablename__ = "friendships"
    id = Column(Integer, primary_key=True, index=True)
    user1 = Column(String, ForeignKey("users.username"), nullable=False)
    user2 = Column(String, ForeignKey("users.username"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String, ForeignKey("users.username"))
    receiver = Column(String, ForeignKey("users.username"))
    encrypted_content = Column(String, nullable=False)
    header_b64 = Column(String, nullable=True)  # Double Ratchet header (needed for decryption)
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_delivered = Column(Boolean, default=False)
    x3dh_ephemeral_public_b64 = Column(String, nullable=True)  # Optional: ephemeral key from X3DH (first message only)
    x3dh_associated_data_b64 = Column(String, nullable=True)  # Optional: associated data from X3DH (first message only)


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
    signing_key_public: str | None = None
    onetime_keys_public: List[str]  # Client should send ~10 onetime public keys


class OneTimeKeyUpload(BaseModel):
    username: str
    onetime_keys_public: List[str]


class PrekeyUpdate(BaseModel):
    username: str
    prekey_public: str
    prekey_signature_public: str


class FriendRequest(BaseModel):
    username: str
    friend_username: str


class AuthChallenge(BaseModel):
    username: str


class AuthVerify(BaseModel):
    username: str
    challenge_response: str


class MessageSend(BaseModel):
    sender: str
    receiver: str
    encrypted_content: str
    header_b64: str = None  # Double Ratchet header (needed for decryption)
    x3dh_ephemeral_public_b64: str = None  # Optional: ephemeral key (first message only)
    x3dh_associated_data_b64: str = None  # Optional: associated data (first message only)


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
    header_b64: str | None = None
    timestamp: datetime
    is_delivered: bool
    x3dh_ephemeral_public_b64: str | None = None
    x3dh_associated_data_b64: str | None = None

    class Config:
        from_attributes = True


class OneTimeKeyOut(BaseModel):
    id: int
    username: str
    onetime_key_public: str
    is_used: bool

    class Config:
        from_attributes = True


ONETIME_KEY_THRESHOLD = 2  # When user has this many keys left, request more
PREKEY_ROTATION_INTERVAL_WEEKS = 1  # Rotate prekeys every week


# --- WebSocket Connection Manager ---
class ConnectionManager:
    """Manages active WebSocket connections for real-time notifications."""

    def __init__(self):
        # Map username -> list of WebSocket connections (supports multiple tabs/devices)
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        if username not in self.active_connections:
            self.active_connections[username] = []
        self.active_connections[username].append(websocket)
        print(f"[WS] {username} connected ({len(self.active_connections[username])} connections)")

    async def disconnect(self, websocket: WebSocket, username: str):
        if username in self.active_connections:
            self.active_connections[username] = [
                ws for ws in self.active_connections[username] if ws != websocket
            ]
            if not self.active_connections[username]:
                del self.active_connections[username]
        print(f"[WS] {username} disconnected")

    async def send_notification(self, username: str, message: dict):
        """Send a notification to all connections of a specific user."""
        if username in self.active_connections:
            dead_connections = []
            for ws in self.active_connections[username]:
                try:
                    await ws.send_json(message)
                except Exception:
                    dead_connections.append(ws)
            # Clean up dead connections
            for ws in dead_connections:
                self.active_connections[username] = [
                    c for c in self.active_connections[username] if c != ws
                ]


manager = ConnectionManager()

# --- Auth Session Storage (in-memory challenge store) ---
auth_sessions: Dict[str, str] = {}  # username -> challenge_hex

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

# CORS middleware to allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- Helper Functions ---

def get_friends_list(username: str, db: Session) -> List[str]:
    """Get list of friend usernames for a given user."""
    friendships = db.query(Friendship).filter(
        or_(Friendship.user1 == username, Friendship.user2 == username)
    ).all()
    friends = []
    for f in friendships:
        friend = f.user2 if f.user1 == username else f.user1
        if friend not in friends:
            friends.append(friend)
    return friends


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

@app.get("/user-exists/{username}", tags=["Authentication"])
def user_exists(username: str, db: Session = Depends(get_db)):
    """Check if a username is already registered."""
    user = db.query(User).filter(User.username == username).first()
    return {"exists": user is not None}


@app.post("/register", tags=["Authentication"])
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
        raise HTTPException(status_code=409, detail="Username already exists. Use /auth/challenge to log in.")

    db_user = User(
        username=user.username,
        public_key=user.public_key,
        identity_key_public=user.identity_key_public,
        prekey_public=user.prekey_public,
        prekey_signature_public=user.prekey_signature_public,
        signing_key_public=user.signing_key_public
    )
    db.add(db_user)

    # Add onetime public keys to the separate table
    for key in user.onetime_keys_public:
        onetime_key = OneTimeKey(username=user.username, onetime_key_public=key)
        db.add(onetime_key)

    db.commit()
    return {"status": "success"}


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

    return {"status": "success", "onetime_keys_public_added": len(data.onetime_keys_public),
            "total_available": keys_status["remaining_onetime_keys"]}


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
        "signing_key_public": user.signing_key_public,
        "onetime_key_public": onetime_key_public_value,
        **keys_status
    }


class PreKeyBundle(BaseModel):
    username: str
    identity_key_public: str
    prekey_public: str
    prekey_signature_public: str
    onetime_key_public: str


@app.get("/get-prekey-bundle/{username}", tags=["User Actions"])
def get_prekey_bundle(username: str, db: Session = Depends(get_db)):
    """
    Get the prekey bundle for a user to start a new conversation.
    Returns:
    - identity_key_public
    - prekey_public
    - prekey_signature_public
    - onetime_key_public
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get an unused onetime key
    onetime_key_record = db.query(OneTimeKey).filter(
        OneTimeKey.username == username,
        OneTimeKey.is_used == False
    ).first()

    if onetime_key_record is None:
        raise HTTPException(status_code=500, detail="No available onetime keys")

    onetime_key_record.is_used = True
    db.commit()

    return PreKeyBundle(
        username=username,
        identity_key_public=user.identity_key_public,
        prekey_public=user.prekey_public,
        prekey_signature_public=user.prekey_signature_public,
        onetime_key_public=onetime_key_record.onetime_key_public,
    )


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


@app.get("/users", response_model=List[UserOut], tags=["User Actions"])
def list_users(db: Session = Depends(get_db)):
    """Get all registered users."""
    return db.query(User).all()


@app.post("/add-friend", tags=["User Actions"])
async def add_friend(data: FriendRequest, db: Session = Depends(get_db)):
    """
    Add a registered user as a friend. Creates a bidirectional friendship
    and triggers a key exchange by fetching the friend's key bundle.
    """
    if data.username == data.friend_username:
        raise HTTPException(status_code=400, detail="Cannot add yourself as a friend")

    # Verify both users exist
    user = db.query(User).filter(User.username == data.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    friend = db.query(User).filter(User.username == data.friend_username).first()
    if not friend:
        raise HTTPException(status_code=404, detail="User not registered. They must register first.")

    # Check if already friends
    existing = db.query(Friendship).filter(
        or_(
            and_(Friendship.user1 == data.username, Friendship.user2 == data.friend_username),
            and_(Friendship.user1 == data.friend_username, Friendship.user2 == data.username)
        )
    ).first()

    if existing:
        return {"status": "already_friends", "message": f"Already friends with {data.friend_username}"}

    # Create friendship (bidirectional - stored once)
    friendship = Friendship(user1=data.username, user2=data.friend_username)
    db.add(friendship)
    db.commit()

    # Notify the friend in real-time that they have a new friend
    await manager.send_notification(data.friend_username, {
        "type": "new_friend",
        "username": data.username
    })

    return {
        "status": "success",
        "message": f"Added {data.friend_username} as friend"
    }


@app.get("/friends/{username}", tags=["User Actions"])
def get_friends(username: str, db: Session = Depends(get_db)):
    """
    Get list of friends for a user with their online status.
    Only returns users that have a friendship record.
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    friends = get_friends_list(username, db)
    friends_with_status = []
    for friend_name in friends:
        friends_with_status.append({
            "username": friend_name
        })

    return {"friends": friends_with_status}


@app.get("/conversation/{user1}/{user2}", tags=["User Actions"])
def get_conversation(user1: str, user2: str, db: Session = Depends(get_db)):
    """Get conversation history between two users."""
    messages = db.query(Message).filter(
        or_(
            and_(Message.sender == user1, Message.receiver == user2),
            and_(Message.sender == user2, Message.receiver == user1)
        )
    ).order_by(Message.timestamp).all()
    return messages


@app.get("/get-public-key/{username}", tags=["User Actions"])
def get_key(username: str, db: Session = Depends(get_db)):
    """Clients call this to get the key needed to encrypt a message for 'username'."""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"username": username, "public_key": user.public_key}


@app.get("/get-identity-key/{username}", tags=["User Actions"])
def get_identity_key(username: str, db: Session = Depends(get_db)):
    """Get the public identity key for a specific user (used for security verification)."""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"username": username, "identity_key_public": user.identity_key_public}


@app.post("/send-message", tags=["User Actions"])
async def send_message(msg: MessageSend, db: Session = Depends(get_db)):
    """Receives an already encrypted blob and stores it for the receiver."""
    receiver = db.query(User).filter(User.username == msg.receiver).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")

    new_msg = Message(
        sender=msg.sender,
        receiver=msg.receiver,
        encrypted_content=msg.encrypted_content,
        header_b64=msg.header_b64,
        x3dh_ephemeral_public_b64=msg.x3dh_ephemeral_public_b64,
        x3dh_associated_data_b64=msg.x3dh_associated_data_b64
    )
    db.add(new_msg)
    db.commit()
    db.refresh(new_msg)

    # Push real-time notification to receiver via WebSocket
    await manager.send_notification(msg.receiver, {
        "type": "new_message",
        "sender": msg.sender,
        "encrypted_content": msg.encrypted_content,
        "header_b64": msg.header_b64,
        "x3dh_ephemeral_public_b64": msg.x3dh_ephemeral_public_b64,
        "x3dh_associated_data_b64": msg.x3dh_associated_data_b64,
        "timestamp": new_msg.timestamp.isoformat(),
        "message_id": new_msg.id
    })

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


# --- WebSocket Endpoint for Real-Time Notifications ---

@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    """
    WebSocket connection for real-time message notifications.
    Client connects after login and receives push notifications
    whenever a new message is sent to them.
    """
    await manager.connect(websocket, username)
    try:
        while True:
            # Keep connection alive; client can send pings or other data
            data = await websocket.receive_text()
            # Echo back a pong for keepalive
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await manager.disconnect(websocket, username)


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

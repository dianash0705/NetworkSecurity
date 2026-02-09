````markdown

# 🔐 Client Service (Crypto Sidecar)

Local FastAPI sidecar that provides cryptographic operations for the **TeeTime** Electron messenger. It implements X3DH key agreement, Double Ratchet message encryption/decryption, and SealedBox authentication. Private keys are kept local to the machine; the sidecar acts as a trusted local service over HTTP.

## 🚀 Features
* **X3DH Key Agreement:** Generate identity keys, signed prekeys, and one-time keys; perform initiator/receiver key exchanges.
* **Double Ratchet Messaging:** Forward-secure end-to-end encryption with per-message ratcheting.
* **SealedBox Authentication:** Challenge-response auth using libsodium SealedBox.
* **Private Key Management:** Private keys never leave the local machine.
* **Automatic API Docs:** Swagger UI available at `/docs`.

---

## 🛠️ Setup Instructions

### 1. Prerequisites
Ensure you have **Python 3.8+** installed.

### 2. Installation
Navigate to the project directory and set up your environment:

```bash
# Enter the client_service/src folder
cd client_service/src

# Create a virtual environment
python -m venv .venv

# Activate the environment
# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# On Windows (CMD):
.\.venv\Scripts\activate.bat
# On Mac/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Running the Sidecar
From the `client_service/src/` directory, run:

```bash
uvicorn service:app --host 127.0.0.1 --port 8765 --reload
```

The sidecar listens on `127.0.0.1:8765` (localhost only for security). The Electron renderer communicates with this sidecar for all cryptographic operations.

---

## 📦 Dependencies
See `client_service/src/requirements.txt`:
- **FastAPI** — Web framework for REST API
- **Pydantic** — Data validation
- **Uvicorn** — ASGI server
- **cryptography** — X25519 key operations for X3DH
- **PyNaCl (pynacl)** — SealedBox encryption/decryption
- **XEdDSA** — EdDSA signatures for prekey verification

---

## 📚 API Endpoints

### X3DH Key Generation

#### `POST /3xdh-create-identity-key`
Generate a new X25519 identity keypair for a user.

**Request:**
```json
{}
```

**Response:**
```json
{
  "x3dh_identity_key": {
    "identity_key_private_b64": "...",
    "identity_key_public_b64": "..."
  }
}
```

**Usage:** Called during user registration. Private key is stored locally by the renderer; public key is uploaded to the central backend.

---

#### `POST /x3dh-create-new-prekey`
Generate a signed prekey using the supplied identity key.

**Request:**
```json
{
  "x3dh_identity_key": {
    "identity_key_private_b64": "...",
    "identity_key_public_b64": "..."
  }
}
```

**Response:**
```json
{
  "prekey_private_b64": "...",
  "prekey_public_b64": "...",
  "prekey_signature_b64": "..."
}
```

**Usage:** Called during registration and prekey rotation. The signature proves that the prekey belongs to the identity key. Private key stays local; public + signature are uploaded to the backend.

---

#### `POST /x3dh-create-onetime-keys`
Generate a batch of one-time X25519 keys for forward secrecy.

**Request:**
```json
{
  "number_of_keys": 10
}
```

**Response:**
```json
{
  "onetime_keys": [
    {
      "onetime_key_private_b64": "...",
      "onetime_key_public_b64": "..."
    },
    ...
  ]
}
```

**Usage:** Called during registration and when one-time key supply is depleted. Private keys are stored locally by the renderer; public keys are uploaded to the backend. Each one-time key is consumed during X3DH to ensure forward secrecy.

---

### X3DH Key Agreement

#### `POST /do-x3dh-by-initiator`
Perform X3DH as the initiator (the peer starting a new conversation).

**Request:**
```json
{
  "self_identity_key_b64": "...",
  "self_identity_key_public_b64": "...",
  "peer_identity_key_public_b64": "...",
  "peer_prekey_public_b64": "...",
  "peer_prekey_signature_b64": "...",
  "peer_onetime_prekey_public_b64": "..."
}
```

**Response:**
```json
{
  "self_ephemeral_key_public_b64": "...",
  "shared_secret_key_b64": "...",
  "associated_data_b64": "..."
}
```

**Usage:** Called when starting a new conversation with a peer. Derives a shared secret that is used to initialize the Double Ratchet session. The ephemeral public key and associated data are sent to the peer.

---

#### `POST /do-x3dh-by-receiver`
Perform X3DH as the receiver (the peer receiving a new conversation).

**Request:**
```json
{
  "self_identity_key_private_b64": "...",
  "self_prekey_private_b64": "...",
  "self_onetime_key_private_b64": "...",
  "peer_identity_key_public_b64": "...",
  "peer_ephemeral_key_public_b64": "..."
}
```

**Response:**
```json
{
  "shared_secret_key_b64": "..."
}
```

**Usage:** Called when receiving the first message in a new conversation. Derives the same shared secret as the initiator using the ephemeral and prekey data. This shared secret initializes the Double Ratchet session.

---

### Message Encryption & Decryption

#### `POST /encrypt-message`
Encrypt a plaintext message using the Double Ratchet protocol.

**Request:**
```json
{
  "state_b64": "...",
  "plaintext_b64": "...",
  "authenticated_data_b64": "..."
}
```

**Response:**
```json
{
  "success": true,
  "state_b64": "...",
  "header_b64": "...",
  "ciphertext_b64": "..."
}
```

**Usage:** Called by the renderer when sending a message. The session state advances with each encryption; the returned `state_b64` must be saved for the next operation. The header contains per-message metadata for decryption.

---

#### `POST /decrypt-message`
Decrypt a ciphertext message using the Double Ratchet protocol.

**Request:**
```json
{
  "state_b64": "...",
  "header_b64": "...",
  "ciphertext_b64": "...",
  "authenticated_data_b64": "..."
}
```

**Response:**
```json
{
  "success": true,
  "state_b64": "...",
  "plaintext": "..."
}
```

**Usage:** Called by the renderer when receiving a message. The session state advances with each decryption; the returned `state_b64` must be saved. The plaintext is returned as a UTF-8 string.

---

### Authentication

#### `POST /sealedbox-decrypt`
Decrypt a libsodium SealedBox ciphertext (used for challenge-response authentication).

**Request:**
```json
{
  "encrypted_b64": "...",
  "public_key_b64": "...",
  "private_key_b64": "..."
}
```

**Response:**
```json
{
  "challenge_hex": "..."
}
```

**Usage:** Called by the renderer during login to decrypt the server's challenge. Proves ownership of the private key. The backend encrypts a random challenge with the user's public key; the renderer decrypts it here and sends the plaintext back to the server for verification.

---

## 🧪 Usage Examples

### Example 1: Register a new user

**Step 1: Generate identity key**
```bash
curl -X POST http://127.0.0.1:8765/3xdh-create-identity-key
```

**Step 2: Generate prekey**
```bash
curl -X POST http://127.0.0.1:8765/x3dh-create-new-prekey \
  -H "Content-Type: application/json" \
  -d '{
    "x3dh_identity_key": {
      "identity_key_private_b64": "...",
      "identity_key_public_b64": "..."
    }
  }'
```

**Step 3: Generate one-time keys**
```bash
curl -X POST http://127.0.0.1:8765/x3dh-create-onetime-keys \
  -H "Content-Type: application/json" \
  -d '{"number_of_keys": 10}'
```

**Step 4:** Upload public keys to the central backend via `/register`.

---

### Example 2: Send an encrypted message

**Step 1: Obtain peer's key bundle from backend**
```bash
GET /get-prekey-bundle/{peer_username}
```

**Step 2: Perform X3DH as initiator**
```bash
curl -X POST http://127.0.0.1:8765/do-x3dh-by-initiator \
  -H "Content-Type: application/json" \
  -d '{
    "self_identity_key_b64": "...",
    "self_identity_key_public_b64": "...",
    "peer_identity_key_public_b64": "...",
    "peer_prekey_public_b64": "...",
    "peer_prekey_signature_b64": "...",
    "peer_onetime_prekey_public_b64": "..."
  }'
```

**Step 3: Initialize Double Ratchet with shared secret** (not yet implemented; manual state construction required)

**Step 4: Encrypt message**
```bash
curl -X POST http://127.0.0.1:8765/encrypt-message \
  -H "Content-Type: application/json" \
  -d '{
    "state_b64": "...",
    "plaintext_b64": "...",
    "authenticated_data_b64": "..."
  }'
```

**Step 5:** Send encrypted content to backend via `POST /send-message`.

---

## 📝 Known Limitations & TODOs

- **Ratchet state serialization:** Currently, `state_b64` is decoded via `json.loads(base64.b64decode(...))` into a Python dict. The Double Ratchet API expects an object with attributes (`state.CKs`, `state.DHs`, etc.). A robust serialization bridge and `/init-ratchet` endpoint are needed.

- **Curve mismatch:** X3DH uses X25519 keys; Double Ratchet currently uses X448. This mismatch breaks DH calculations. Align both to X25519.

- **No state persistence:** Session state is passed as base64 strings between renderer and sidecar. No server-side state storage; the renderer must manage and update state locally.

- **One-time key tracking:** The sidecar does not track one-time key consumption. The renderer and backend must coordinate to mark used keys.

---

## 🔭 Next Steps

1. **Implement `/init-ratchet` endpoint:** Convert X3DH shared secret into a proper Double Ratchet `state_b64`.
2. **Add state serialization helpers:** Deterministic JSON serialization/deserialization for ratchet state.
3. **Align curves:** Port Double Ratchet to X25519 or X3DH to X448.
4. **Unit tests:** Test X3DH round-trips and ratchet state transitions.

---

## 🔒 Security Notes

- **Private keys:** All private keys generated by this sidecar are returned to the caller. The renderer must store them securely (e.g., in `localStorage` with appropriate warnings).
- **Localhost only:** Sidecar binds to `127.0.0.1:8765`. Never expose to the network.
- **No persistence:** Sidecar does not store private keys. The renderer is responsible for key storage.
- **HTTPS for backend:** Ensure the central backend communication uses HTTPS in production.

```

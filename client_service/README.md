````markdown

# 🔐 Client Service (local sidecar)

Local FastAPI sidecar that provides X3DH key generation/agreements and Double Ratchet encrypt/decrypt primitives used by the Electron renderer. Its goal is to keep private keys local to the machine and expose cryptographic operations over a trusted loopback HTTP API.

## 🚀 What this component provides
- Key generation helpers for X3DH (identity, signed prekeys, one-time keys).
- X3DH initiator/receiver endpoints to derive shared secrets used to initialize a Double Ratchet session.
- Double Ratchet encrypt/decrypt wrappers that advance session state on each operation.

## 📂 Location
- Core server: [client_service/src/service.py](client_service/src/service.py)
- Protocol implementations: [client_service/src/signal_protocol/x3dh.py](client_service/src/signal_protocol/x3dh.py), [client_service/src/signal_protocol/double_ratchet_impl.py](client_service/src/signal_protocol/double_ratchet_impl.py), [client_service/src/signal_protocol/double_ratchet_api.py](client_service/src/signal_protocol/double_ratchet_api.py)

---

## 🛠️ Setup Instructions

### 1. Prerequisites
Ensure you have **Python 3.8+** installed.

### 2. Installation
From the `client_service/src` folder create and activate a virtual environment, install requirements, and run the sidecar:

```powershell
cd client_service/src
python -m venv .venv
# On PowerShell
.\.venv\Scripts\Activate.ps1
# On CMD
.\.venv\Scripts\activate.bat
# On Mac/Linux
# source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Running the sidecar

```bash
uvicorn service:app --host 127.0.0.1 --port 8765 --reload
```

The sidecar exposes JSON endpoints used by the Electron renderer to perform local cryptographic operations.

---

## 📦 Dependencies
- See `client_service/src/requirements.txt` (FastAPI, pydantic, cryptography, uvicorn, xeddsa bindings).

---

## 🔑 Important endpoints (summary)

- `POST /3xdh-create-identity-key`
  - Description: Generate a new X25519 identity keypair.
  - Response: base64 private + public (private must stay local).

- `POST /x3dh-create-new-prekey`
  - Description: Create a signed prekey using supplied identity key.
  - Input: identity key pair (private_b64 + public_b64)
  - Response: prekey private/public and signature (base64)

- `POST /x3dh-create-onetime-keys`
  - Description: Generate a batch of one-time X25519 keys for upload to the central server.
  - Input: `{ number_of_keys: int }` (default 10)
  - Response: array of `{ onetime_key_private_b64, onetime_key_public_b64 }`

- `POST /do-x3dh-by-initiator`
  - Description: Run X3DH as initiator; returns shared secret and ephemeral public key.
  - Use: Derive symmetric material for ratchet initialization.

- `POST /do-x3dh-by-receiver`
  - Description: Run X3DH as receiver to derive same shared secret when receiving the first message.

- `POST /encrypt-message`
  - Description: Double Ratchet encryption wrapper.
  - Input: `{ state_b64, plaintext_b64, authenticated_data_b64 }`
  - Output: advanced `state_b64`, `header_b64`, `ciphertext_b64`.
  - NOTE: The current implementation expects `state_b64` to decode into the protocol's in-memory `state` structure. See TODOs below — state serialization/deserialization is not yet standardized.

- `POST /decrypt-message`
  - Description: Double Ratchet decryption wrapper.
  - Input: `{ state_b64, header_b64, ciphertext_b64, authenticated_data_b64 }`
  - Output: advanced `state_b64`, plaintext (bytes returned raw in the existing code).

---

## 🧪 Usage examples

1) Generate identity key (client registration flow):

```bash
curl -X POST http://127.0.0.1:8765/3xdh-create-identity-key
```

2) Generate a batch of one-time keys:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"number_of_keys":10}' http://127.0.0.1:8765/x3dh-create-onetime-keys
```

---

## 📝 Notes & important TODOs

- **Ratchet state serialization:** `service.py` currently decodes `state_b64` via `json.loads(base64.b64decode(...))` and passes the result to the Double Ratchet API, which expects an object with attributes (e.g. `state.CKs`, `state.DHs`, etc.). There is currently no canonical serializer/deserializer bridging the Python `state` object and a safe JSON representation. Implementing a `ratchet-init` + `serialize_state`/`deserialize_state` pair is required for reliable operation.

- **Curve mismatch:** the X3DH implementation uses X25519 keys while the Double Ratchet implementation currently uses X448 (`X448PrivateKey`/`X448PublicKey`) in `double_ratchet_impl.py`. This mismatch is significant — you should either port the ratchet to X25519 or align X3DH to X448. Leaving them mismatched will break DH calculations.

- **Security:** private keys returned by endpoints are sensitive and must remain local. Do NOT send private keys to any remote or untrusted server.

- **One-time key consumption:** server-side endpoints in your central backend (not this sidecar) mark one-time keys as used when issuing prekey bundles. The sidecar returns private one-time keys so the client can keep them; ensure the client marks a key as consumed locally after use.

- **Tests & validation:** add unit tests for `x3dh.x3dh_by_initiator` / `x3dh_by_receiver` round-trip and for `RatchetInitAlice`/`RatchetInitBob` once a consistent curve choice is decided.

---

## 🔭 Next steps

- Implement deterministic ratchet state serialization & an `/init-ratchet` endpoint that consumes the X3DH shared secret and returns a serialized `state_b64` ready for `/encrypt-message`.
- Align the elliptic curve choice between X3DH and Double Ratchet (X25519 vs X448).

If you want, I can implement a `ratchet-init` endpoint and a serializer next. (I can also align the curves if you prefer X25519 for both.)

```

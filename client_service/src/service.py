import base64
import json
import logging
import traceback

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from nacl.public import PrivateKey as NaClPrivateKey, PublicKey as NaClPublicKey, SealedBox

import signal_protocol.double_ratchet_api as double_ratchet
from signal_protocol import x3dh
from signal_protocol.double_ratchet_impl import DHKeyPair
from signal_protocol.x3dh import IdentityKeyPair

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("client_service")

app = FastAPI()

# ============================================================================
# DOUBLE RATCHET ENCRYPTION / DECRYPTION ENDPOINTS
# ============================================================================
# These endpoints handle message encryption and decryption using the
# Double Ratchet protocol (Signal Protocol). They maintain and advance
# the ratchet session state with each encryption/decryption operation.
# ============================================================================

class EncryptRequest(BaseModel):
    state_b64: str
    plaintext_b64: str
    authenticated_data_b64: str


class EncryptResponse(BaseModel):
    success: bool
    state_b64: str
    header_b64: str
    ciphertext_b64: str

def fix_state_objects(state):
    """
    Helper to ensure RatchetState objects (DH keys) are correctly instantiated 
    as cryptography objects, not raw bytes/dicts, after deserialization.
    """
    # Fix DHs (Sender Key Pair) - might be a dict of bytes
    if hasattr(state, 'DHs') and isinstance(state.DHs, dict):
        try:
            priv_bytes = state.DHs.get('private')
            pub_bytes = state.DHs.get('public')
            if isinstance(priv_bytes, bytes) and isinstance(pub_bytes, bytes):
                priv = X25519PrivateKey.from_private_bytes(priv_bytes)
                pub = X25519PublicKey.from_public_bytes(pub_bytes)
                state.DHs = DHKeyPair(priv, pub)
        except Exception as e:
            logger.error(f"Failed to reconstruct DHs: {e}")

    # Fix DHr (Receiver Public Key) - might be bytes
    if hasattr(state, 'DHr') and isinstance(state.DHr, bytes):
        try:
            state.DHr = X25519PublicKey.from_public_bytes(state.DHr)
        except Exception as e:
            logger.error(f"Failed to reconstruct DHr: {e}")
    return state

@app.post("/encrypt-message")
# Encrypts a plaintext message using the current Double Ratchet session state.
# INPUT: state_b64 (serialized ratchet state), plaintext_b64, authenticated_data_b64
# OUTPUT: encrypted message header, ciphertext, and advanced session state
# USE: Called by renderer.js when sending a message to encrypt it end-to-end
def encrypt_message(encrypt_request: EncryptRequest) -> EncryptResponse:
    try:
        plaintext = base64.b64decode(encrypt_request.plaintext_b64)
        authenticated_data = base64.b64decode(encrypt_request.authenticated_data_b64)

        # Deserialize state from JSON (state comes in as base64-encoded JSON dict)
        state_dict = json.loads(base64.b64decode(encrypt_request.state_b64))
        state = double_ratchet.deserialize_state(state_dict)
        state = fix_state_objects(state)

        header, ciphertext = double_ratchet.RatchetEncrypt(state, plaintext, authenticated_data)

        # Serialize state back to JSON for transport
        state_serialized = double_ratchet.serialize_state(state)
        state_b64 = base64.b64encode(json.dumps(state_serialized).encode()).decode()

        response = EncryptResponse(
            success=True,
            state_b64=state_b64,
            header_b64=base64.b64encode(header).decode(),
            ciphertext_b64=base64.b64encode(ciphertext).decode(),
        )

        return response
    except Exception as e:
        tb = traceback.format_exc()
        logger.exception("encrypt_message failed")
        detail = f"encrypt_message error: {type(e).__name__}: {str(e)}\n{tb[:1500]}"
        raise HTTPException(status_code=400, detail=detail)


class DecryptRequest(BaseModel):
    state_b64: str
    header_b64: str
    ciphertext_b64: str
    authenticated_data_b64: str


class DecryptResponse(BaseModel):
    success: bool
    state_b64: str
    plaintext: str


@app.post("/decrypt-message")
# Decrypts a ciphertext message using the current Double Ratchet session state.
# INPUT: state_b64, header_b64, ciphertext_b64, authenticated_data_b64
# OUTPUT: decrypted plaintext and advanced session state
# USE: Called by renderer.js when receiving a message to decrypt it end-to-end
def decrypt_message(decrypt_request: DecryptRequest) -> DecryptResponse:
    try:
        header = base64.b64decode(decrypt_request.header_b64)
        ciphertext = base64.b64decode(decrypt_request.ciphertext_b64)
        authenticated_data = base64.b64decode(decrypt_request.authenticated_data_b64)

        # Deserialize state from JSON
        state_dict = json.loads(base64.b64decode(decrypt_request.state_b64))
        state = double_ratchet.deserialize_state(state_dict)
        state = fix_state_objects(state)

        plaintext = double_ratchet.RatchetDecrypt(state, header, ciphertext, authenticated_data)

        # Serialize state back to JSON for transport
        state_serialized = double_ratchet.serialize_state(state)
        state_b64 = base64.b64encode(json.dumps(state_serialized).encode()).decode()

        response = DecryptResponse(
            success=True,
            state_b64=state_b64,
            plaintext=plaintext
        )

        return response
    except Exception as e:
        tb = traceback.format_exc()
        logger.exception("decrypt_message failed")
        detail = f"decrypt_message error: {type(e).__name__}: {str(e)}\n{tb[:1500]}"
        raise HTTPException(status_code=400, detail=detail)


class InitRatchetRequest(BaseModel):
    shared_secret_b64: str
    bob_dh_public_key_b64: str
    role: str  # "sender" or "receiver"


class InitRatchetResponse(BaseModel):
    success: bool
    state_b64: str


@app.post("/init-ratchet")
# Initializes a new Double Ratchet session using a shared secret from X3DH.
# INPUT: shared_secret_b64, bob_dh_public_key_b64, role ("sender" or "receiver")
# OUTPUT: { state_b64 (serialized initial ratchet state) }
# USE: Called after X3DH key agreement to set up the ratchet session for a conversation.
#      The initiator (sender) and responder (receiver) use different initialization paths.
def init_ratchet(request: InitRatchetRequest) -> InitRatchetResponse:
    try:
        shared_secret = base64.b64decode(request.shared_secret_b64)
        bob_dh_public_key_bytes = base64.b64decode(request.bob_dh_public_key_b64)
        bob_dh_public_key = X25519PublicKey.from_public_bytes(bob_dh_public_key_bytes)
        
        # Create initial state object
        state = double_ratchet.RatchetState()
        
        if request.role == "sender":
            # Sender: call RatchetInitAlice
            double_ratchet.RatchetInitAlice(state, shared_secret, bob_dh_public_key)
        elif request.role == "receiver":
            # Receiver: generate DH keypair and call RatchetInitBob
            # bob_dh_public_key_bytes is actually the receiver's private key here
            bob_dh_private_key = X25519PrivateKey.from_private_bytes(bob_dh_public_key_bytes)
            bob_dh_public_key_obj = bob_dh_private_key.public_key()
            bob_dh_key_pair = DHKeyPair(bob_dh_private_key, bob_dh_public_key_obj)
            double_ratchet.RatchetInitBob(state, shared_secret, bob_dh_key_pair)
        else:
            raise ValueError("role must be 'sender' or 'receiver'")
        
        # Serialize state to JSON for transport
        state_serialized = double_ratchet.serialize_state(state)
        state_b64 = base64.b64encode(json.dumps(state_serialized).encode()).decode()
        
        return InitRatchetResponse(
            success=True,
            state_b64=state_b64
        )
    except Exception as e:
        tb = traceback.format_exc()
        logger.exception("init_ratchet failed")
        detail = f"init_ratchet error: {type(e).__name__}: {str(e)}\n{tb[:1500]}"
        raise HTTPException(status_code=400, detail=detail)


class X3DHIdentityKey(BaseModel):
    identity_key_private_b64: str
    identity_key_public_b64: str
    signing_key_private_b64: str | None = None
    signing_key_public_b64: str | None = None


class X3DHCreateIdentityKeyResponse(BaseModel):
    x3dh_identity_key: X3DHIdentityKey


# ============================================================================
# X3DH (TRIPLE DIFFIE-HELLMAN) KEY GENERATION ENDPOINTS
# ============================================================================
# X3DH is the key agreement protocol used to establish a shared secret
# between two peers before initializing the Double Ratchet session.
# ============================================================================

@app.post("/3xdh-create-identity-key")
# Creates a new X25519 identity key pair for a user.
# INPUT: None
# OUTPUT: { identity_key_private_b64, identity_key_public_b64 }
# USE: Called during user registration to generate the identity key.
#      Private key is stored locally; public key is registered with central server.
def x3dh_create_identity_key() -> X3DHCreateIdentityKeyResponse:
    identity_key_pair = x3dh.create_identity_key()

    return X3DHCreateIdentityKeyResponse(x3dh_identity_key=X3DHIdentityKey(
        identity_key_private_b64=base64.b64encode(identity_key_pair.identity_key_private.private_bytes_raw()).decode(),
        identity_key_public_b64=base64.b64encode(identity_key_pair.identity_key_public.public_bytes_raw()).decode(),
        signing_key_private_b64=base64.b64encode(identity_key_pair.signing_key_private_bytes).decode(),
        signing_key_public_b64=base64.b64encode(identity_key_pair.signing_key_public_bytes).decode(),
    ), )


class X3DHCreateNewPreKeyRequest(BaseModel):
    x3dh_identity_key: X3DHIdentityKey


class X3DHCreateNewPreKeyResponse(BaseModel):
    prekey_private_b64: str
    prekey_public_b64: str
    prekey_signature_b64: str


@app.post("/x3dh-create-new-prekey")
# Creates a new signed prekey for X3DH key agreement.
# INPUT: { identity_key_private_b64, identity_key_public_b64 }
# OUTPUT: { prekey_private_b64, prekey_public_b64, prekey_signature_b64 }
# USE: Called to generate prekeys published on the server.
#      Signature allows peers to verify the prekey during X3DH.
def x3dh_create_new_prekey(request: X3DHCreateNewPreKeyRequest) -> X3DHCreateNewPreKeyResponse:
    ik_priv = X25519PrivateKey.from_private_bytes(base64.b64decode(request.x3dh_identity_key.identity_key_private_b64))
    ik_pub = X25519PublicKey.from_public_bytes(base64.b64decode(request.x3dh_identity_key.identity_key_public_b64))
    signing_priv_bytes = None
    signing_pub_bytes = None
    if request.x3dh_identity_key.signing_key_private_b64:
        signing_priv_bytes = base64.b64decode(request.x3dh_identity_key.signing_key_private_b64)
    if request.x3dh_identity_key.signing_key_public_b64:
        signing_pub_bytes = base64.b64decode(request.x3dh_identity_key.signing_key_public_b64)

    identity_key_pair = IdentityKeyPair(
        identity_key_private=ik_priv,
        identity_key_public=ik_pub,
        signing_key_private_bytes=signing_priv_bytes,
        signing_key_public_bytes=signing_pub_bytes,
    )

    prekey_pair = x3dh.create_new_prekey(identity_key_pair)

    return X3DHCreateNewPreKeyResponse(
        prekey_private_b64=base64.b64encode(prekey_pair.prekey_private.private_bytes_raw()).decode(),
        prekey_public_b64=base64.b64encode(prekey_pair.prekey_public.public_bytes_raw()).decode(),
        prekey_signature_b64=base64.b64encode(prekey_pair.prekey_signature).decode(),
    )


class X3DHCreateOnetimeKeysRequest(BaseModel):
    number_of_keys: int = 10


class X3DHCreateOnetimeKeysResponse(BaseModel):
    onetime_keys: list


@app.post("/x3dh-create-onetime-keys")
# Creates a batch of one-time key pairs for X3DH key agreement.
# INPUT: { number_of_keys (default: 10) }
# OUTPUT: { onetime_keys: [ { onetime_key_private_b64, onetime_key_public_b64 }, ... ] }
# USE: Called to generate one-time keys published on the server.
#      Peers consume one-time keys during X3DH to ensure forward secrecy.
#      Keys should be regenerated periodically or when depleted.
def x3dh_create_onetime_keys(request: X3DHCreateOnetimeKeysRequest) -> X3DHCreateOnetimeKeysResponse:
    onetime_keys_obj = x3dh.generate_one_time_keys(request.number_of_keys)
    
    onetime_keys_list = []
    for otk in onetime_keys_obj.one_time_keys:
        onetime_keys_list.append({
            "onetime_key_private_b64": base64.b64encode(otk.one_time_prekey_private.private_bytes_raw()).decode(),
            "onetime_key_public_b64": base64.b64encode(otk.one_time_prekey_public.public_bytes_raw()).decode(),
        })
    
    return X3DHCreateOnetimeKeysResponse(onetime_keys=onetime_keys_list)


class SealedBoxDecryptRequest(BaseModel):
    encrypted_b64: str
    public_key_b64: str
    private_key_b64: str


class SealedBoxDecryptResponse(BaseModel):
    challenge_hex: str


@app.post("/sealedbox-decrypt")
def sealedbox_decrypt(req: SealedBoxDecryptRequest) -> SealedBoxDecryptResponse:
    """
    Decrypt a libsodium-style SealedBox ciphertext.
    INPUT: encrypted_b64, public_key_b64, private_key_b64
    OUTPUT: { challenge_hex }
    Note: This endpoint is intended to be called on localhost from the trusted renderer.
    """
    try:
        ciphertext = base64.b64decode(req.encrypted_b64)
        # PyNaCl SealedBox requires the recipient's private key to open
        priv = NaClPrivateKey(base64.b64decode(req.private_key_b64))
        sealed = SealedBox(priv)
        plaintext = sealed.decrypt(ciphertext)
        return SealedBoxDecryptResponse(challenge_hex=plaintext.hex())
    except Exception as e:
        tb = traceback.format_exc()
        logger.exception("sealedbox_decrypt failed")
        detail = f"SealedBox decryption failed: {type(e).__name__}: {str(e)}\n{tb[:1500]}"
        raise HTTPException(status_code=400, detail=detail)


class DoX3DHByInitiatorReqeust(BaseModel):
    self_identity_key_b64: str
    self_identity_key_public_b64: str
    peer_identity_key_public_b64: str
    peer_prekey_public_b64: str
    peer_prekey_signature_b64: str
    peer_onetime_prekey_public_b64: str
    peer_signing_key_public_b64: str | None = None


class DoX3DHByInitiatorResponse(BaseModel):
    self_ephemeral_key_public_b64: str
    shared_secret_key_b64: str
    associated_data_b64: str


# ============================================================================
# X3DH KEY AGREEMENT ENDPOINTS
# ============================================================================
# These endpoints perform the actual X3DH computation to derive a shared
# secret between two peers. One peer acts as initiator, the other as receiver.
# ============================================================================

@app.post("/do-x3dh-by-initiator")
# Performs X3DH key agreement as the initiator (sender opening a new conversation).
# INPUT: initiator's identity/prekeys + peer's public prekeys (fetched from server)
# OUTPUT: { shared_secret_key_b64, self_ephemeral_key_public_b64, associated_data_b64 }
# USE: Called when starting a new conversation with a peer.
#      Derives shared secret used to initialize the Double Ratchet session.
def do_x3dh_by_initiator(request: DoX3DHByInitiatorReqeust) -> DoX3DHByInitiatorResponse:
    try:
        self_identity_key = X25519PrivateKey.from_private_bytes(base64.b64decode(request.self_identity_key_b64))
        self_identity_key_public = X25519PublicKey.from_public_bytes(base64.b64decode(request.self_identity_key_public_b64))
        peer_identity_key_public = X25519PublicKey.from_public_bytes(base64.b64decode(request.peer_identity_key_public_b64))
        peer_prekey_public = X25519PublicKey.from_public_bytes(base64.b64decode(request.peer_prekey_public_b64))
        peer_prekey_signature: bytes = base64.b64decode(request.peer_prekey_signature_b64)
        peer_onetime_prekey_public = X25519PublicKey.from_public_bytes(base64.b64decode(request.peer_onetime_prekey_public_b64))
        peer_signing_pub_bytes = None
        if request.peer_signing_key_public_b64:
            peer_signing_pub_bytes = base64.b64decode(request.peer_signing_key_public_b64)

        # Log the incoming signature and keys (base64) for easier debugging
        try:
            logger.debug(f"do_x3dh_by_initiator: peer_prekey_signature_b64={request.peer_prekey_signature_b64}")
            logger.debug(f"do_x3dh_by_initiator: peer_identity_key_public_b64={request.peer_identity_key_public_b64}")
            logger.debug(f"do_x3dh_by_initiator: peer_prekey_public_b64={request.peer_prekey_public_b64}")
        except Exception:
            logger.debug("do_x3dh_by_initiator: failed to log key material")

        x3dh_initiator_result = x3dh.x3dh_by_initiator(
            self_identity_key,
            self_identity_key_public,
            peer_identity_key_public,
            peer_prekey_public,
            peer_prekey_signature,
            peer_onetime_prekey_public,
            peer_signing_pub_bytes,
        )

        return DoX3DHByInitiatorResponse(
            self_ephemeral_key_public_b64=base64.b64encode(
                x3dh_initiator_result.self_ephemeral_key_public.public_bytes_raw()).decode(),
            shared_secret_key_b64=base64.b64encode(x3dh_initiator_result.shared_secret_key).decode(),
            associated_data_b64=base64.b64encode(x3dh_initiator_result.associated_data).decode(),
        )
    except Exception as e:
        tb = traceback.format_exc()
        logger.exception("do_x3dh_by_initiator failed")
        detail = f"X3DH initiator failed: {type(e).__name__}: {str(e)}\n{tb[:1500]}"
        raise HTTPException(status_code=400, detail=detail)


class DoX3DHByReceiverReqeust(BaseModel):
    self_identity_key_private_b64: str
    self_prekey_private_b64: str
    self_onetime_key_private_b64: str
    peer_identity_key_public_b64: str
    peer_ephemeral_key_public_b64: str


class DoX3DHByReceiverResponse(BaseModel):
    shared_secret_key_b64: str


@app.post("/do-x3dh-by-receiver")
# Performs X3DH key agreement as the receiver (recipient receiving first message).
# INPUT: receiver's prekeys + initiator's ephemeral/identity public keys
# OUTPUT: { shared_secret_key_b64 }
# USE: Called when receiving the first message in a new conversation.
#      Derives same shared secret as initiator for symmetric session initialization.
def do_x3dh_by_receiver(request: DoX3DHByReceiverReqeust) -> DoX3DHByReceiverResponse:
    try:
        self_identity_key_private = X25519PrivateKey.from_private_bytes(
            base64.b64decode(request.self_identity_key_private_b64))
        self_prekey_private = X25519PrivateKey.from_private_bytes(base64.b64decode(request.self_prekey_private_b64))
        self_onetime_key_private = X25519PrivateKey.from_private_bytes(
            base64.b64decode(request.self_onetime_key_private_b64))
        peer_identity_key_public = X25519PublicKey.from_public_bytes(base64.b64decode(request.peer_identity_key_public_b64))
        peer_ephemeral_key_public = X25519PublicKey.from_public_bytes(base64.b64decode(request.peer_ephemeral_key_public_b64))

        x3dh_receiver_result = x3dh.x3dh_by_receiver(
            self_identity_key_private,
            self_prekey_private,
            self_onetime_key_private,
            peer_identity_key_public,
            peer_ephemeral_key_public,
        )

        return DoX3DHByReceiverResponse(
            shared_secret_key_b64=base64.b64encode(x3dh_receiver_result.shared_secret_key).decode(),
        )
    except Exception as e:
        tb = traceback.format_exc()
        logger.exception("do_x3dh_by_receiver failed")
        detail = f"X3DH receiver failed: {type(e).__name__}: {str(e)}\n{tb[:1500]}"
        raise HTTPException(status_code=400, detail=detail)

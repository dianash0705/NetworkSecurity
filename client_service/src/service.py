import base64
import json

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from fastapi import FastAPI
from pydantic import BaseModel

import signal_protocol.double_ratchet_api as double_ratchet
from client_service.src.signal_protocol import x3dh
from client_service.src.signal_protocol.x3dh import IdentityKeyPair

app = FastAPI()


class EncryptRequest(BaseModel):
    state_b64: str
    plaintext_b64: str
    authenticated_data_b64: str


class EncryptResponse(BaseModel):
    success: bool
    state_b64: str
    header_b64: str
    ciphertext_b64: str


@app.post("/encrypt_message")
def encrypt_message(encrypt_request: EncryptRequest) -> EncryptResponse:
    plaintext = base64.b64decode(encrypt_request.plaintext_b64)
    authenticated_data = base64.b64decode(encrypt_request.authenticated_data_b64)

    state = json.loads(base64.b64decode(encrypt_request.state_b64))

    header, ciphertext = double_ratchet.RatchetEncrypt(state, plaintext, authenticated_data)

    response = EncryptResponse(
        success=True,
        state_b64=base64.b64encode(state).decode(),
        header_b64=base64.b64encode(header).decode(),
        ciphertext_b64=base64.b64encode(ciphertext).decode(),
    )

    return response


class DecryptRequest(BaseModel):
    state_b64: str
    header_b64: str
    ciphertext_b64: str
    authenticated_data_b64: str


class DecryptResponse(BaseModel):
    success: bool
    state_b64: str
    plaintext: str


@app.post("/decrypt_message")
def encrypt_message(decrypt_request: DecryptRequest) -> DecryptResponse:
    header = base64.b64decode(decrypt_request.header_b64)
    ciphertext = base64.b64decode(decrypt_request.ciphertext_b64)
    authenticated_data = base64.b64decode(decrypt_request.authenticated_data_b64)

    state = json.loads(base64.b64decode(decrypt_request.state_b64))

    plaintext = double_ratchet.RatchetDecrypt(state, header, ciphertext, authenticated_data)

    response = DecryptResponse(
        success=True,
        state_b64=base64.b64encode(state).decode(),
        plaintext=plaintext
    )

    return response


class X3DHIdentityKey(BaseModel):
    identity_key_private_b64: str
    identity_key_public_b64: str


class X3DHCreateIdentityKeyResponse(BaseModel):
    x3dh_identity_key: X3DHIdentityKey


@app.post("/3xdh_create_identity_key")
def x3dh_create_identity_key() -> X3DHCreateIdentityKeyResponse:
    identity_key_pair = x3dh.create_identity_key()

    return X3DHCreateIdentityKeyResponse(x3dh_identity_key=X3DHIdentityKey(
        identity_key_private_b64=base64.b64encode(identity_key_pair.identity_key_private.private_bytes_raw()).decode(),
        identity_key_public_b64=base64.b64encode(identity_key_pair.identity_key_public.public_bytes_raw()).decode(),
    ), )


class X3DHCreateNewPreKeyRequest(BaseModel):
    x3dh_identity_key: X3DHIdentityKey


class X3DHCreateNewPreKeyResponse(BaseModel):
    prekey_private_b64: str
    prekey_public_b64: str
    prekey_signature_b64: str


@app.post("/x3dh_create_new_prekey")
def x3dh_create_new_prekey(request: X3DHCreateNewPreKeyRequest) -> X3DHCreateNewPreKeyResponse:
    ik_priv = X25519PrivateKey.from_private_bytes(base64.b64decode(request.x3dh_identity_key.identity_key_private_b64))
    ik_pub = X25519PublicKey.from_public_bytes(base64.b64decode(request.x3dh_identity_key.identity_key_public_b64))

    identity_key_pair = IdentityKeyPair(
        identity_key_private=ik_priv, identity_key_public=ik_pub
    )

    prekey_pair = x3dh.create_new_prekey(identity_key_pair)

    return X3DHCreateNewPreKeyResponse(
        prekey_private_b64=base64.b64encode(prekey_pair.prekey_private.private_bytes_raw()).decode(),
        prekey_public_b64=base64.b64encode(prekey_pair.prekey_public.public_bytes_raw()).decode(),
        prekey_signature_b64=base64.b64encode(prekey_pair.prekey_signature).decode(),
    )


class DoX3DHByInitiatorReqeust(BaseModel):
    self_identity_key_b64: str
    self_identity_key_public_b64: str
    peer_identity_key_public_b64: str
    peer_prekey_public_b64: str
    peer_prekey_signature_b64: str
    peer_onetime_prekey_public_b64: str


class DoX3DHByInitiatorResponse(BaseModel):
    self_ephemeral_key_public_b64: str
    shared_secret_key_b64: str
    associated_data_b64: str


@app.post("/do_x3dh_by_initiator")
def do_x3dh_by_initiator(request: DoX3DHByInitiatorReqeust) -> DoX3DHByInitiatorResponse:
    self_identity_key = X25519PrivateKey.from_private_bytes(base64.b64decode(request.self_identity_key))
    self_identity_key_public = X25519PublicKey.from_public_bytes(base64.b64decode(request.self_identity_key_public))
    peer_identity_key_public = X25519PublicKey.from_public_bytes(base64.b64decode(request.peer_identity_key_public))
    peer_prekey_public = X25519PublicKey.from_public_bytes(base64.b64decode(request.peer_prekey_public))
    peer_prekey_signature: bytes = base64.b64decode(request.peer_prekey_signature)
    peer_onetime_prekey_public = X25519PublicKey.from_public_bytes(base64.b64decode(request.peer_onetime_prekey_public))

    x3dh_initiator_result = x3dh.x3dh_by_initiator(
        self_identity_key,
        self_identity_key_public,
        peer_identity_key_public,
        peer_prekey_public,
        peer_prekey_signature,
        peer_onetime_prekey_public
    )

    return DoX3DHByInitiatorResponse(
        self_ephemeral_key_public_b64=base64.b64encode(
            x3dh_initiator_result.self_ephemeral_key_public.public_bytes_raw()).decode(),
        shared_secret_key_b64=base64.b64encode(x3dh_initiator_result.shared_secret_key).decode(),
        associated_data_b64=base64.b64encode(x3dh_initiator_result.associated_data).decode(),
    )


class DoX3DHByReceiverReqeust(BaseModel):
    self_identity_key_private_b64: str
    self_prekey_private_b64: str
    self_onetime_key_private_b64: str
    peer_identity_key_public_b64: str
    peer_ephemeral_key_public_b64: str


class DoX3DHByReceiverResponse(BaseModel):
    shared_secret_key_b64: str


@app.post("/do_x3dh_by_receiver")
def do_x3dh_by_receiver(request: DoX3DHByReceiverReqeust) -> DoX3DHByReceiverResponse:
    self_identity_key_private = X25519PrivateKey.from_private_bytes(
        base64.b64decode(request.self_identity_key_private_b64))
    self_prekey_private = X25519PrivateKey.from_private_bytes(base64.b64decode(request.self_prekey_private_b64))
    self_onetime_key_private = X25519PrivateKey.from_private_bytes(
        base64.b64decode(request.self_onetime_key_private_b64))
    peer_identity_key_public = X25519PublicKey.from_public_bytes(base64.b64decode(request.peer_identity_key_public_b64))
    peer_ephemeral_key_public = X25519PublicKey.from_public_bytes(base64.b64decode(request.peer_prekey_public_b64))

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

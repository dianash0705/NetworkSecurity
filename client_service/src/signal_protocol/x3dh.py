import base64
import json
from dataclasses import dataclass

import xeddsa.bindings
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel

CURVE = X25519PrivateKey
HASH = hashes.SHA256
INFO = b"tea_time_x3dh_info"


def kdf(secret_key_material: bytes) -> bytes:
    KDF_OUTPUT_BYTES_LEN = 32
    SALT = b'\0' * KDF_OUTPUT_BYTES_LEN

    F = b'\xff' * 32  # len is 32 because curve is X25519, other curves, other len

    key_material = F + secret_key_material

    return HKDF(
        algorithm=HASH(),
        length=KDF_OUTPUT_BYTES_LEN,
        salt=SALT,
        info=INFO,
    ).derive(key_material)


class CreateIdentityRequest(BaseModel):
    pass


class Identity(BaseModel):
    identity_key_private_b64: str
    identity_key_public_b64: str
    prekey_private_b64: str
    prekey_public_b64: str
    prekey_signature: str


class CreateIdentityResponse(BaseModel):
    identity: Identity


def create_identity(create_identity_request: CreateIdentityRequest) -> CreateIdentityResponse:
    identity_key_private = CURVE.generate()
    identity_key_public = identity_key_private.public_key()

    prekey_private = CURVE.generate()
    prekey_public = prekey_private.public_key()

    prekey_signature = xeddsa.bindings.ed25519_priv_sign(priv=identity_key_private.private_bytes_raw(),
                                                         msg=prekey_public.public_bytes_raw())

    return CreateIdentityResponse(identity=Identity(
        identity_key_private_b64=base64.b64encode(identity_key_private.private_bytes_raw()).decode(),
        identity_key_public_b64=base64.b64encode(identity_key_public.public_bytes_raw()).decode(),
        prekey_private_b64=base64.b64encode(prekey_private.private_bytes_raw()).decode(),
        prekey_public_b64=base64.b64encode(prekey_public.public_bytes_raw()).decode(),
        prekey_signature=base64.b64encode(prekey_signature).decode()
    ))


class GenerateOneTimeKeysRequest(BaseModel):
    count: int


class OneTimeKeyPair(BaseModel):
    one_time_prekey_private_b64: str
    one_time_prekey_public_b64: str


class GenerateOneTimeKeysResponse(BaseModel):
    one_time_keys: list[OneTimeKeyPair]


def generate_one_time_keys(generate_one_time_key_request: GenerateOneTimeKeysRequest) -> GenerateOneTimeKeysResponse:
    one_time_keys = []

    for i in range(generate_one_time_key_request.count):
        private_key = CURVE.generate()
        public_key = private_key.public_key()

        one_time_key_pair = OneTimeKeyPair(
            one_time_prekey_private_b64=base64.b64encode(private_key.private_bytes_raw()).decode(),
            one_time_prekey_public_b64=base64.b64encode(public_key.public_bytes_raw()).decode(),
        )

        one_time_keys.append(one_time_key_pair)

    return GenerateOneTimeKeysResponse(one_time_keys=one_time_keys)


class PeerPreKeyBundle(BaseModel):
    peer_identity_key_public_b64: str
    peer_prekey_public_b64: str
    peer_prekey_signature_b64: str
    peer_one_time_prekey_public_b64: str


class X3DHHandshakeRequest(BaseModel):
    self_identity: Identity
    peer_prekey_bundle: PeerPreKeyBundle


class X3DHHandshakeResponse(BaseModel):
    secret_key_b64: str


def x3dhh_handshake(x3dh_req: X3DHHandshakeRequest) -> X3DHHandshakeResponse:
    pass


@dataclass(frozen=True)
class X3DHResult:
    self_ephemeral_key_public: X25519PublicKey
    shared_secret_key: bytes
    associated_data: bytes


def x3dh(
        self_identity_key: X25519PrivateKey,
        self_identity_key_public: X25519PublicKey,
        peer_identity_key_public: X25519PublicKey,
        peer_prekey_public: X25519PublicKey,
        peer_prekey_signature: bytes,
        peer_onetime_prekey_public: X25519PublicKey,
) -> X3DHResult:
    ephemeral_private_key = CURVE.generate()
    ephemeral_public_key = ephemeral_private_key.public_key()

    verification_successful = xeddsa.bindings.ed25519_verify(sig=peer_prekey_signature,
                                                             ed25519_pub=peer_identity_key_public.public_bytes_raw(),
                                                             msg=peer_prekey_public.public_bytes_raw())

    if not verification_successful:
        raise ValueError("verification failed")

    dh1 = self_identity_key.exchange(peer_prekey_public)
    dh2 = ephemeral_private_key.exchange(peer_identity_key_public)
    dh3 = ephemeral_private_key.exchange(peer_prekey_public)
    dh4 = ephemeral_private_key.exchange(peer_onetime_prekey_public)

    secret_key = kdf(dh1 + dh2 + dh3 + dh4)

    associated_data = base64.b64encode(json.dumps({
        "sender_identity_key_b64": base64.b64encode(self_identity_key_public.public_bytes_raw()).decode(),
        "receiver_identity_key_b64": base64.b64encode(peer_identity_key_public.public_bytes_raw()).decode(),
    }).encode())

    # TODO: aead the data first

    return X3DHResult(

    )

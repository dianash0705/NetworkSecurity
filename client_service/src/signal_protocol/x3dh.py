import base64
import json
from dataclasses import dataclass

import xeddsa.bindings
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CURVE = X25519PrivateKey
HASH = hashes.SHA256
INFO = b"tea_time_x3dh_info"

XEDDSA_BIT_SET = False


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


@dataclass(frozen=True)
class IdentityKeyPair:
    identity_key_private: X25519PrivateKey
    identity_key_public: X25519PublicKey


@dataclass(frozen=True)
class PreKeyPair:
    prekey_private: X25519PrivateKey
    prekey_public: X25519PublicKey
    prekey_signature: bytes


def create_identity_key() -> IdentityKeyPair:
    identity_key_private = CURVE.generate()
    identity_key_public = identity_key_private.public_key()

    identity_key = IdentityKeyPair(
        identity_key_private=identity_key_private,
        identity_key_public=identity_key_public,
    )

    return identity_key


def create_new_prekey(identity_key: IdentityKeyPair) -> PreKeyPair:
    prekey_private = CURVE.generate()
    prekey_public = prekey_private.public_key()

    modified_private_key = xeddsa.bindings.priv_force_sign(
        identity_key.identity_key_private.private_bytes_raw(),
        XEDDSA_BIT_SET
    )

    prekey_signature = xeddsa.bindings.ed25519_priv_sign(
        priv=modified_private_key,
        msg=prekey_public.public_bytes_raw()
    )

    prekey = PreKeyPair(
        prekey_private=prekey_private,
        prekey_public=prekey_public,
        prekey_signature=prekey_signature,
    )

    return prekey


@dataclass(frozen=True)
class OneTimeKeyPair:
    one_time_prekey_private: X25519PrivateKey
    one_time_prekey_public: X25519PublicKey


@dataclass(frozen=True)
class OneTimeKeys:
    one_time_keys: list[OneTimeKeyPair]


def generate_one_time_keys(number_of_keys_to_generate: int) -> OneTimeKeys:
    one_time_keys = []

    for i in range(number_of_keys_to_generate):
        private_key = CURVE.generate()
        public_key = private_key.public_key()

        one_time_key_pair = OneTimeKeyPair(
            one_time_prekey_private=private_key,
            one_time_prekey_public=public_key,
        )

        one_time_keys.append(one_time_key_pair)

    return OneTimeKeys(one_time_keys=one_time_keys)


@dataclass(frozen=True)
class X3DHInitiatorResult:
    self_ephemeral_key_public: X25519PublicKey
    shared_secret_key: bytes
    associated_data: bytes


def x3dh_by_initiator(
        self_identity_key: X25519PrivateKey,
        self_identity_key_public: X25519PublicKey,
        peer_identity_key_public: X25519PublicKey,
        peer_prekey_public: X25519PublicKey,
        peer_prekey_signature: bytes,
        peer_onetime_prekey_public: X25519PublicKey,
) -> X3DHInitiatorResult:
    ephemeral_private_key = CURVE.generate()
    ephemeral_public_key = ephemeral_private_key.public_key()

    identity_key_xeddesa_public_key = xeddsa.bindings.curve25519_pub_to_ed25519_pub(
        peer_identity_key_public.public_bytes_raw(), XEDDSA_BIT_SET)

    verification_successful = xeddsa.bindings.ed25519_verify(
        sig=peer_prekey_signature,
        ed25519_pub=identity_key_xeddesa_public_key,
        msg=peer_prekey_public.public_bytes_raw()
    )

    if not verification_successful:
        sig_b64 = base64.b64encode(peer_prekey_signature).decode()
        id_pub_b64 = base64.b64encode(peer_identity_key_public.public_bytes_raw()).decode()
        prekey_pub_b64 = base64.b64encode(peer_prekey_public.public_bytes_raw()).decode()
        raise ValueError(
            f"verification failed; sig_b64={sig_b64}; id_pub_b64={id_pub_b64}; prekey_pub_b64={prekey_pub_b64}")

    dh1 = self_identity_key.exchange(peer_prekey_public)
    dh2 = ephemeral_private_key.exchange(peer_identity_key_public)
    dh3 = ephemeral_private_key.exchange(peer_prekey_public)
    dh4 = ephemeral_private_key.exchange(peer_onetime_prekey_public)

    secret_key = kdf(dh1 + dh2 + dh3 + dh4)

    associated_data = base64.b64encode(json.dumps({
        "sender_identity_key_b64": base64.b64encode(self_identity_key_public.public_bytes_raw()).decode(),
        "receiver_identity_key_b64": base64.b64encode(peer_identity_key_public.public_bytes_raw()).decode(),
    }).encode())

    return X3DHInitiatorResult(
        self_ephemeral_key_public=ephemeral_public_key,
        shared_secret_key=secret_key,
        associated_data=associated_data,
    )


@dataclass(frozen=True)
class X3DHReceiverResult:
    shared_secret_key: bytes


def x3dh_by_receiver(
        self_identity_key_private: X25519PrivateKey,
        self_prekey_private: X25519PrivateKey,
        self_onetime_key_private: X25519PrivateKey,
        peer_identity_key_public: X25519PublicKey,
        peer_ephemeral_key_public: X25519PublicKey,
):
    dh1 = self_prekey_private.exchange(peer_identity_key_public)
    dh2 = self_identity_key_private.exchange(peer_ephemeral_key_public)
    dh3 = self_prekey_private.exchange(peer_ephemeral_key_public)
    dh4 = self_onetime_key_private.exchange(peer_ephemeral_key_public)

    secret_key = kdf(dh1 + dh2 + dh3 + dh4)

    return X3DHReceiverResult(
        shared_secret_key=secret_key,
    )

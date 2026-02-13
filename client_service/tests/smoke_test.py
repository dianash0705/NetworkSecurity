import base64
import json
import logging
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from client_service.src.signal_protocol.double_ratchet_api import RatchetInitAlice, RatchetInitBob
from signal_protocol import double_ratchet_impl, double_ratchet_api
from signal_protocol import x3dh
from signal_protocol.double_ratchet_impl import DHKeyPair, DoubleRatchetState, DoubleRatchetHeader
from signal_protocol.x3dh import IdentityKeyPair

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("signal_smoketest")


# ----------------------------
# Helpers matching your API
# ----------------------------

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode() if isinstance(s, str) else s)


def state_to_b64(state) -> str:
    d = double_ratchet_impl.double_ratchet_state_to_dict(state)
    return b64e(json.dumps(d).encode())


def state_from_b64(state_b64: str):
    d = json.loads(b64d(state_b64))
    return double_ratchet_impl.deserialize_double_ratchet_state(d)


# ----------------------------
# X3DH "server bundle" model
# ----------------------------

@dataclass
class BobBundle:
    bob_identity_pub: X25519PublicKey
    bob_signed_prekey_pub: X25519PublicKey
    bob_signed_prekey_sig: bytes
    bob_one_time_prekey_pub: X25519PublicKey

    # kept privately by Bob (not published)
    bob_identity_priv: X25519PrivateKey
    bob_signed_prekey_priv: X25519PrivateKey
    bob_one_time_prekey_priv: X25519PrivateKey


def make_identity_pair() -> IdentityKeyPair:
    # Uses your x3dh helper to match your endpoint behavior
    ik = x3dh.create_identity_key()
    return ik


def make_bob_bundle() -> BobBundle:
    bob_ik = make_identity_pair()

    # Signed prekey
    spk = x3dh.create_new_prekey(bob_ik)

    # One-time prekey: your endpoint has field mixups; do it directly here safely
    otks = x3dh.generate_one_time_keys(1)
    otk_obj = otks.one_time_keys[0]
    bob_otk_priv = otk_obj.one_time_prekey_private
    bob_otk_pub = otk_obj.one_time_prekey_public

    return BobBundle(
        bob_identity_pub=bob_ik.identity_key_public,
        bob_signed_prekey_pub=spk.prekey_public,
        bob_signed_prekey_sig=spk.prekey_signature,
        bob_one_time_prekey_pub=bob_otk_pub,
        bob_identity_priv=bob_ik.identity_key_private,
        bob_signed_prekey_priv=spk.prekey_private,
        bob_one_time_prekey_priv=bob_otk_priv,
    )


# ----------------------------
# Encrypt/decrypt wrappers
# ----------------------------

def ratchet_encrypt(state, plaintext: bytes, ad: bytes) -> Tuple[str, bytes, str]:
    header, ciphertext = double_ratchet_api.RatchetEncrypt(state, plaintext, ad)
    serialized_header = double_ratchet_impl.double_ratchet_header_serialize(header)
    return serialized_header, ciphertext, state_to_b64(state)


def ratchet_decrypt(state, header_serialized: str, ciphertext: bytes, ad: bytes) -> Tuple[bytes, str]:
    header = double_ratchet_impl.double_ratchet_header_deserialize(header_serialized)
    pt = double_ratchet_api.RatchetDecrypt(state, header, ciphertext, ad)
    return pt, state_to_b64(state)


# ----------------------------
# The actual smoke test
# ----------------------------

def main():
    logger.info("=== 1) Create identities ===")
    alice_ik = make_identity_pair()
    bob_bundle = make_bob_bundle()

    logger.info("Alice IK pub: %s", b64e(alice_ik.identity_key_public.public_bytes_raw())[:20] + "...")
    logger.info("Bob   IK pub: %s", b64e(bob_bundle.bob_identity_pub.public_bytes_raw())[:20] + "...")

    logger.info("=== 2) X3DH (Alice initiator) ===")
    x3dh_init = x3dh.x3dh_by_initiator(
        alice_ik.identity_key_private,
        alice_ik.identity_key_public,
        bob_bundle.bob_identity_pub,
        bob_bundle.bob_signed_prekey_pub,
        bob_bundle.bob_signed_prekey_sig,
        bob_bundle.bob_one_time_prekey_pub,
    )
    alice_shared = x3dh_init.shared_secret_key
    alice_ad = x3dh_init.associated_data
    alice_eph_pub = x3dh_init.self_ephemeral_key_public

    logger.info("Alice shared: %s", b64e(alice_shared)[:20] + "...")
    logger.info("Alice eph pub: %s", b64e(alice_eph_pub.public_bytes_raw())[:20] + "...")

    logger.info("=== 3) X3DH (Bob receiver) ===")
    x3dh_recv = x3dh.x3dh_by_receiver(
        bob_bundle.bob_identity_priv,
        bob_bundle.bob_signed_prekey_priv,
        bob_bundle.bob_one_time_prekey_priv,
        alice_ik.identity_key_public,
        alice_eph_pub,
    )
    bob_shared = x3dh_recv.shared_secret_key

    logger.info("Bob shared:   %s", b64e(bob_shared)[:20] + "...")
    assert alice_shared == bob_shared, "X3DH shared secret mismatch!"
    logger.info("✅ X3DH shared secret matches")

    logger.info("=== 4) Init Double Ratchet ===")
    # Per your comment: Bob’s signed prekey becomes Bob’s initial ratchet key.
    bob_ratchet_pub_bytes = bob_bundle.bob_signed_prekey_pub.public_bytes_raw()

    alice_state = DoubleRatchetState()
    bob_state = DoubleRatchetState()

    RatchetInitAlice(alice_state, alice_shared, bob_ratchet_pub_bytes)
    RatchetInitBob(
        bob_state,
        alice_shared,
        DHKeyPair(bob_bundle.bob_signed_prekey_priv, bob_bundle.bob_signed_prekey_pub)
    )

    logger.info("✅ Double Ratchet initialized")

    # Authenticated data: in Signal this is usually context (identities, etc).
    # For smoke test, just reuse the X3DH associated_data.
    ad = alice_ad

    logger.info("=== 5) Exchange 3 messages ===")

    # ---- Msg 1: Alice -> Bob
    msg1 = b"hi bob (1)"
    header1, ct1, alice_state_b64 = ratchet_encrypt(alice_state, msg1, ad)
    alice_state = state_from_b64(alice_state_b64)

    pt1, bob_state_b64 = ratchet_decrypt(bob_state, header1, ct1, ad)
    bob_state = state_from_b64(bob_state_b64)

    assert pt1 == msg1, "Bob failed to decrypt msg1"
    logger.info("✅ Bob decrypted msg1: %r", pt1)

    # ---- Msg 2: Bob -> Alice
    msg2 = b"hi alice (2)"
    header2, ct2, bob_state_b64 = ratchet_encrypt(bob_state, msg2, ad)
    bob_state = state_from_b64(bob_state_b64)

    pt2, alice_state_b64 = ratchet_decrypt(alice_state, header2, ct2, ad)
    alice_state = state_from_b64(alice_state_b64)

    assert pt2 == msg2, "Alice failed to decrypt msg2"
    logger.info("✅ Alice decrypted msg2: %r", pt2)

    # ---- Msg 3: Alice -> Bob
    msg3 = b"nice, works (3)"
    header3, ct3, alice_state_b64 = ratchet_encrypt(alice_state, msg3, ad)
    alice_state = state_from_b64(alice_state_b64)

    pt3, bob_state_b64 = ratchet_decrypt(bob_state, header3, ct3, ad)
    bob_state = state_from_b64(bob_state_b64)

    assert pt3 == msg3, "Bob failed to decrypt msg3"
    logger.info("✅ Bob decrypted msg3: %r", pt3)

    logger.info("🎉 ALL GOOD: X3DH + Double Ratchet message flow succeeded.")


if __name__ == "__main__":
    main()

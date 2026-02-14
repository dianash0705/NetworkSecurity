import base64
import json
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

AES_BLOCKSIZE_BITS = 128


@dataclass(frozen=True)
class DHKeyPair:
    private_key: X25519PrivateKey
    public_key: X25519PublicKey


def GENERATE_DH() -> DHKeyPair:
    sk = X25519PrivateKey.generate()
    vk = sk.public_key()
    return DHKeyPair(sk, vk)


def DH(dh_pair: DHKeyPair, dh_pub: bytes) -> bytes:
    return dh_pair.private_key.exchange(X25519PublicKey.from_public_bytes(dh_pub))


def KDF_RK(rk, dh_out) -> (bytes, bytes):
    DOUBLE_RATCHET_KDF_RK_INFO = b"double_ratchet_kdf_rk"

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=rk,
        info=DOUBLE_RATCHET_KDF_RK_INFO,
    ).derive(dh_out)
    # Return two 32-byte values derived from HKDF output
    return derived_key[0:32], derived_key[32:64]


def KDF_CK(ck) -> (bytes, bytes):
    if ck is None:
        raise ValueError("Invalid CK")

    MESSAGE_KEY_CONST = b'\x01'
    CHAIN_KEY_CONST = b'\x02'

    message_key_hmac = hmac.HMAC(ck, hashes.SHA256())
    message_key_hmac.update(MESSAGE_KEY_CONST)
    message_key = message_key_hmac.finalize()

    chain_key_hmac = hmac.HMAC(ck, hashes.SHA256())
    chain_key_hmac.update(CHAIN_KEY_CONST)
    chain_key = chain_key_hmac.finalize()

    return chain_key, message_key


def ENCRYPT(mk, plaintext, associated_data):
    DOUBLE_RATCHET_ENCRYPT_HKDF_INFO = b"double_ratchet_encrypt"
    ENCRYPT_HKDF_OUT_LEN = 80

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=ENCRYPT_HKDF_OUT_LEN,
        salt=b'\0' * ENCRYPT_HKDF_OUT_LEN,
        info=DOUBLE_RATCHET_ENCRYPT_HKDF_INFO,
    ).derive(mk)

    # Split HKDF output into 32-byte encryption key, 32-byte auth key, 16-byte IV
    encryption_key = derived_key[0:32]
    authentication_key = derived_key[32:64]
    iv = derived_key[64:80]

    padder = padding.PKCS7(AES_BLOCKSIZE_BITS).padder()
    padded_plaintext = padder.update(plaintext)
    padded_plaintext += padder.finalize()

    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    hmaccer = hmac.HMAC(authentication_key, hashes.SHA256())
    hmaccer.update(associated_data + ciphertext)
    tag = hmaccer.finalize()

    return ciphertext + tag


def DECRYPT(mk, ciphertext, associated_data):
    DOUBLE_RATCHET_ENCRYPT_HKDF_INFO = b"double_ratchet_encrypt"
    ENCRYPT_HKDF_OUT_LEN = 80

    ciphertext_without_tag = ciphertext[:-32]
    tag = ciphertext[-32:]

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=ENCRYPT_HKDF_OUT_LEN,
        salt=b'\0' * ENCRYPT_HKDF_OUT_LEN,
        info=DOUBLE_RATCHET_ENCRYPT_HKDF_INFO,
    ).derive(mk)

    encryption_key = derived_key[0:32]
    authentication_key = derived_key[32:64]
    iv = derived_key[64:80]

    hmaccer = hmac.HMAC(authentication_key, hashes.SHA256())
    hmaccer.update(associated_data + ciphertext_without_tag)
    hmaccer.verify(tag)

    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
    decrypter = cipher.decryptor()
    padded_plaintext = decrypter.update(ciphertext_without_tag) + decrypter.finalize()

    unpadder = padding.PKCS7(AES_BLOCKSIZE_BITS).unpadder()
    plaintext = unpadder.update(padded_plaintext)
    plaintext += unpadder.finalize()

    return plaintext


@dataclass
class DoubleRatchetHeader:
    dh: bytes
    pn: int
    n: int


def HEADER(dh_pair: DHKeyPair, pn, n):
    return DoubleRatchetHeader(
        dh=dh_pair.public_key.public_bytes_raw(),
        pn=pn,
        n=n,
    )


def double_ratchet_header_serialize(header: DoubleRatchetHeader) -> str:
    return base64.b64encode(json.dumps({
        "dh_b64": base64.b64encode(header.dh).decode(),
        "pn": header.pn,
        "n": header.n,
    }).encode()).decode()


def double_ratchet_header_deserialize(header_bytes: str) -> DoubleRatchetHeader:
    header_dict = json.loads(base64.b64decode(header_bytes).decode())
    return DoubleRatchetHeader(dh=base64.b64decode(header_dict['dh_b64']), pn=header_dict['pn'], n=header_dict['n'])


def CONCAT(ad, header):
    serialized_header = double_ratchet_header_serialize(header).encode()
    len_ad_len_header = struct.pack('<QQ', len(ad), len(serialized_header))
    return len_ad_len_header + ad + serialized_header


class DoubleRatchetState:
    def __init__(self):
        self.DHs = None  # DHKeyPair
        self.DHr = None  # X25519PublicKey
        self.RK = None  # bytes
        self.CKs = None  # bytes
        self.CKr = None  # bytes
        self.Ns = 0  # int
        self.Nr = 0  # int
        self.PN = 0  # int
        self.MKSKIPPED = {}  # dict


def double_ratchet_state_to_dict(state: DoubleRatchetState) -> dict[str, ...]:
    """
    Convert a RatchetState object to a JSON-serializable dict (base64 encoded).
    Returns a dict that can be json.dumps() -> base64 encoded.
    """
    state_dict = {
        "DHs": {
            "private": base64.b64encode(state.DHs.private_key.private_bytes_raw()).decode(),
            "public": base64.b64encode(state.DHs.public_key.public_bytes_raw()).decode(),
        } if state.DHs else None,
        "DHr_b64": base64.b64encode(state.DHr).decode() if state.DHr else None,
        "RK": base64.b64encode(state.RK).decode() if state.RK else None,
        "CKs": base64.b64encode(state.CKs).decode() if state.CKs else None,
        "CKr": base64.b64encode(state.CKr).decode() if state.CKr else None,
        "Ns": state.Ns,
        "Nr": state.Nr,
        "PN": state.PN,
        "MKSKIPPED": {
            f"{base64.b64encode(k[0].public_bytes_raw()).decode()}_{k[1]}": base64.b64encode(v).decode()
            for k, v in state.MKSKIPPED.items()
        }
    }
    return state_dict


def deserialize_double_ratchet_state(state_dict: dict[str, ...]) -> DoubleRatchetState:
    """
    Reconstruct a RatchetState object from a JSON dict (with base64-encoded values).
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

    state = DoubleRatchetState()

    # Reconstruct DHs (DHKeyPair)
    if state_dict.get("DHs"):
        priv_bytes = base64.b64decode(state_dict["DHs"]["private"])
        pub_bytes = base64.b64decode(state_dict["DHs"]["public"])
        priv_key = X25519PrivateKey.from_private_bytes(priv_bytes)
        pub_key = X25519PublicKey.from_public_bytes(pub_bytes)
        state.DHs = DHKeyPair(priv_key, pub_key)

    if state_dict.get("DHr_b64"):
        state.DHr = base64.b64decode(state_dict["DHr_b64"])

    # Reconstruct byte strings
    state.RK = base64.b64decode(state_dict["RK"]) if state_dict.get("RK") else None
    state.CKs = base64.b64decode(state_dict["CKs"]) if state_dict.get("CKs") else None
    state.CKr = base64.b64decode(state_dict["CKr"]) if state_dict.get("CKr") else None

    # Reconstruct integers
    state.Ns = state_dict.get("Ns", 0)
    state.Nr = state_dict.get("Nr", 0)
    state.PN = state_dict.get("PN", 0)

    # Reconstruct MKSKIPPED (dict of tuples → bytes)
    state.MKSKIPPED = {}
    if state_dict.get("MKSKIPPED"):
        for key_str, val_b64 in state_dict["MKSKIPPED"].items():
            parts = key_str.rsplit("_", 1)
            if len(parts) == 2:
                pub_b64, n_str = parts
                dh_pub_bytes = base64.b64decode(pub_b64)
                n = int(n_str)
                state.MKSKIPPED[(dh_pub_bytes, n)] = base64.b64decode(val_b64)

    return state

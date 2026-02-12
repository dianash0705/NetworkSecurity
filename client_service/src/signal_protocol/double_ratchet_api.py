# Notes:
# Task is create an IM app using signal protocol.
# This design doc helped me implement it by myself https://signal.org/docs/specifications/doubleratchet/

# region __External_Functions__
# https://signal.org/docs/specifications/doubleratchet/#dr-external-functions

from .double_ratchet_impl import GENERATE_DH, DH, KDF_RK, KDF_CK, ENCRYPT, DECRYPT, HEADER, CONCAT, parse_header

# def GENERATE_DH():
#     raise NotImplementedError
#
# def DH(dh_pair, dh_pub):
#     raise NotImplementedError
#
# def KDF_RK(rk, dh_out):
#     raise NotImplementedError
#
# def KDF_CK(ck):
#     raise NotImplementedError
#
# def ENCRYPT(mk, plaintext, associated_data):
#     raise NotImplementedError
#
# def DECRYPT(mk, ciphertext, associated_data):
#     raise NotImplementedError
#
# def HEADER(dh_pair, pn, n):
#     raise NotImplementedError
#
# def CONCAT(ad, header):
#     raise NotImplementedError

# endregion __External_Functions__

# region __Initialization__
# https://signal.org/docs/specifications/doubleratchet/#dr-initialization



# sending first message, Alice is the initiator, Bob is the responder
def RatchetInitAlice(state, SK, bob_dh_public_key):
    state.DHs = GENERATE_DH()
    state.DHr = bob_dh_public_key
    state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr))
    state.CKr = None
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MKSKIPPED = {}

# receiving first message, Bob is the responder, Alice is the initiator
def RatchetInitBob(state, SK, bob_dh_key_pair):
    state.DHs = bob_dh_key_pair
    state.DHr = None
    state.RK = SK
    state.CKs = None
    state.CKr = None
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MKSKIPPED = {}

# endregion __Initialization__

# region __Encrypt_Messages__
# https://signal.org/docs/specifications/doubleratchet/#dr-encrypting-messages

def RatchetSendKey(state):
    state.CKs, mk = KDF_CK(state.CKs)
    Ns = state.Ns
    state.Ns += 1
    return Ns, mk

def RatchetEncrypt(state, plaintext, AD):
    Ns, mk = RatchetSendKey(state)
    header = HEADER(state.DHs, state.PN, Ns)
    return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))

# endregion __Encrypt_Messages__

# region __Decrypt_Messages__
# https://signal.org/docs/specifications/doubleratchet/#dr-decrypting-messages

# region TODO
MAX_SKIP=1000
Error=NotImplementedError
# endregion TODO

def RatchetReceiveKey(state, header):
    mk = TrySkippedMessageKeys(state, header)
    if mk != None:
        return mk
    if header.dh != state.DHr:
        SkipMessageKeys(state, header.pn)
        DHRatchet(state, header)
    SkipMessageKeys(state, header.n)
    state.CKr, mk = KDF_CK(state.CKr)
    state.Nr += 1
    return mk

def RatchetDecrypt(state, header_bytes, ciphertext, AD):
    header_obj = parse_header(header_bytes)
    mk = RatchetReceiveKey(state, header_obj)
    return DECRYPT(mk, ciphertext, CONCAT(AD, header_bytes))

def TrySkippedMessageKeys(state, header):
    dh_bytes = header.dh.public_bytes_raw()
    if (dh_bytes, header.n) in state.MKSKIPPED:
        mk = state.MKSKIPPED[dh_bytes, header.n]
        del state.MKSKIPPED[dh_bytes, header.n]
        return mk
    else:
        return None

def SkipMessageKeys(state, until):
    if state.Nr + MAX_SKIP < until:
        raise Error()
    if state.CKr != None:
        while state.Nr < until:
            state.CKr, mk = KDF_CK(state.CKr)
            dh_bytes = state.DHr.public_bytes_raw()
            state.MKSKIPPED[dh_bytes, state.Nr] = mk
            state.Nr += 1

def DHRatchet(state, header):
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0
    state.DHr = header.dh
    state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs, state.DHr))
    state.DHs = GENERATE_DH()
    state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs, state.DHr))

# endregion __Decrypt_Messages__


# ============================================================================
# STATE SERIALIZATION / DESERIALIZATION
# ============================================================================
# Converts ratchet state between a Python object and a JSON-serializable dict

import base64


class RatchetState:
    """Container for Double Ratchet state attributes."""
    def __init__(self):
        self.DHs = None  # DHKeyPair
        self.DHr = None  # X25519PublicKey
        self.RK = None   # bytes
        self.CKs = None  # bytes
        self.CKr = None  # bytes
        self.Ns = 0      # int
        self.Nr = 0      # int
        self.PN = 0      # int
        self.MKSKIPPED = {}  # dict


def serialize_state(state):
    """
    Convert a RatchetState object to a JSON-serializable dict (base64 encoded).
    Returns a dict that can be json.dumps() -> base64 encoded.
    """
    state_dict = {
        "DHs": {
            "private": base64.b64encode(state.DHs.private_key.private_bytes_raw()).decode(),
            "public": base64.b64encode(state.DHs.public_key.public_bytes_raw()).decode(),
        } if state.DHs else None,
        "DHr": base64.b64encode(state.DHr.public_bytes_raw()).decode() if state.DHr else None,
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


def deserialize_state(state_dict):
    """
    Reconstruct a RatchetState object from a JSON dict (with base64-encoded values).
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    
    state = RatchetState()
    
    # Reconstruct DHs (DHKeyPair)
    if state_dict.get("DHs"):
        priv_bytes = base64.b64decode(state_dict["DHs"]["private"])
        pub_bytes = base64.b64decode(state_dict["DHs"]["public"])
        priv_key = X25519PrivateKey.from_private_bytes(priv_bytes)
        pub_key = X25519PublicKey.from_public_bytes(pub_bytes)
        from .double_ratchet_impl import DHKeyPair
        state.DHs = DHKeyPair(priv_key, pub_key)
    
    # Reconstruct DHr (X25519PublicKey)
    if state_dict.get("DHr"):
        state.DHr = X25519PublicKey.from_public_bytes(base64.b64decode(state_dict["DHr"]))
    
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
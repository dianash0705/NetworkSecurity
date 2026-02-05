# Notes:
# Task is create an IM app using signal protocol.
# This design doc helped me implement it by myself https://signal.org/docs/specifications/doubleratchet/

# region __External_Functions__
# https://signal.org/docs/specifications/doubleratchet/#dr-external-functions

from double_ratchet_impl import GENERATE_DH, DH, KDF_RK, KDF_CK, ENCRYPT, DECRYPT, HEADER, CONCAT

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

def RatchetInitAlice(state, SK, bob_dh_public_key):
    state.DHs = GENERATE_DH()
    state.DHr = bob_dh_public_key
    state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr))
    state.CKr = None
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MKSKIPPED = {}

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

def RatchetDecrypt(state, header, ciphertext, AD):
    mk = RatchetReceiveKey(state, header)
    return DECRYPT(mk, ciphertext, CONCAT(AD, header))

def TrySkippedMessageKeys(state, header):
    if (header.dh, header.n) in state.MKSKIPPED:
        mk = state.MKSKIPPED[header.dh, header.n]
        del state.MKSKIPPED[header.dh, header.n]
        return mk
    else:
        return None

def SkipMessageKeys(state, until):
    if state.Nr + MAX_SKIP < until:
        raise Error()
    if state.CKr != None:
        while state.Nr < until:
            state.CKr, mk = KDF_CK(state.CKr)
            state.MKSKIPPED[state.DHr, state.Nr] = mk
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
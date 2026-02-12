import base64
import json
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_BLOCKSIZE_BITS = 128


@dataclass(frozen=True)
class DHKeyPair:
    private_key: X25519PrivateKey
    public_key: X25519PublicKey


def GENERATE_DH() -> DHKeyPair:
    sk = X25519PrivateKey.generate()
    vk = sk.public_key()
    return DHKeyPair(sk, vk)


def DH(dh_pair: DHKeyPair, dh_pub: X25519PublicKey) -> bytes:
    return dh_pair.private_key.exchange(dh_pub)


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

    return message_key, chain_key


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


def HEADER(dh_pair: DHKeyPair, pn, n):
    return json.dumps(
        {
            "public_key": base64.b64encode(dh_pair.public_key.public_bytes_raw()).decode(),
            "pn": pn,
            "n": n,
        }
    ).encode()

def CONCAT(ad, header):
    len_ad_len_header  = struct.pack('<QQ', len(ad), len(header))
    return len_ad_len_header + ad + header

@dataclass(frozen=True)
class HeaderObj:
    dh: X25519PublicKey
    pn: int
    n: int

def parse_header(header_bytes: bytes) -> HeaderObj:
    data = json.loads(header_bytes.decode())
    dh_bytes = base64.b64decode(data['public_key'])
    dh = X25519PublicKey.from_public_bytes(dh_bytes)
    return HeaderObj(dh=dh, pn=data['pn'], n=data['n'])

import base64
import json

from fastapi import FastAPI
from pydantic import BaseModel

import signal_protocol.double_ratchet_api as double_ratchet

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

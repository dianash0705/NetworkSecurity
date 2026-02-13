from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from xeddsa.bindings import (
    ed25519_priv_sign,
    ed25519_verify,
    priv_to_ed25519_pub
)

# 1. Generate the key using the cryptography library
identity_key_private = X25519PrivateKey.generate()

# 2. Extract the raw 32 bytes (the "Priv" type alias)
# The bindings API requires raw bytes, not the object itself
priv_bytes = identity_key_private.private_bytes_raw()

# 3. Derive the corresponding Ed25519 public key
# XEdDSA allows the X25519 private key to sign as an Ed25519 key
public_key_bytes = priv_to_ed25519_pub(priv_bytes)

# 4. Sign a message
message = b"Authenticated via XEdDSA"
signature = ed25519_priv_sign(priv_bytes, message)

# 5. Verify the signature
is_valid = ed25519_verify(signature, public_key_bytes, message)

print(f"Verified: {is_valid}")
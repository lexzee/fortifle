import ctypes
import os

# Load DLL
lib = ctypes.CDLL(os.path.abspath("mldsa.dll"))

# Constants (from api.h or README)
CRYPTO_PUBLICKEYBYTES = 1312
CRYPTO_SECRETKEYBYTES = 2528
CRYPTO_BYTES = 2420

# Alloc buffers
pk = ctypes.create_string_buffer(CRYPTO_PUBLICKEYBYTES)
sk = ctypes.create_string_buffer(CRYPTO_SECRETKEYBYTES)
sig = ctypes.create_string_buffer(CRYPTO_BYTES)
siglen = ctypes.c_size_t()

# Message to sign
message = b"ML-DSA post-quantum signature test"
msglen = len(message)

# Generate keypair
res = lib.sign_keypair(pk, sk)
assert res == 0, "ML-DSA key genration failed"
print("ML-DSA keypair generated.")

# sign Message
res = lib.sign_message(sig, ctypes.byref(siglen), message, msglen, sk)
assert res == 0, "Failed to sign message"
print(f"Message signed ({siglen.value} bytes).")

# Verify Signature
res = lib.verify_signature(sig, siglen.value, message, msglen, pk)
print("Signature Verified." if res == 0 else "Verification failed.")
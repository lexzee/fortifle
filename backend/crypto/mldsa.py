import ctypes
import os

# Load DLL
DLL_PATH = os.path.join(os.path.dirname(__file__), '../pqclean_wrappers/dilithium/mldsa.dll')
lib = ctypes.CDLL(os.path.abspath(DLL_PATH))


# Constants (from api.h or README)
CRYPTO_PUBLICKEYBYTES = 1952
CRYPTO_SECRETKEYBYTES = 4032
CRYPTO_BYTES = 3309

# Message to sign
message = b"ML-DSA post-quantum signature test"
msglen = len(message)

# Generate keypair
def gen_keypair():
  print("[KEYPAIR] Generating ML-DSA keypair...")
  pk = ctypes.create_string_buffer(CRYPTO_PUBLICKEYBYTES)
  sk = ctypes.create_string_buffer(CRYPTO_SECRETKEYBYTES)
  res = lib.sign_keypair(pk, sk)
  if res != 0:
    raise RuntimeError("ML-DSA keypair generation failed.")
  return pk.raw, sk.raw

# sign Message
def sign_message(message: bytes, sk_bytes: bytes) -> bytes:
  print("[SIGN] Signing message...")
  sig = ctypes.create_string_buffer(CRYPTO_BYTES)
  siglen = ctypes.c_size_t()
  msglen = len(message)
  sk = ctypes.create_string_buffer(sk_bytes)
  res = lib.sign_message(sig, ctypes.byref(siglen), message, msglen, sk)
  if res != 0:
      raise RuntimeError("Signing failed.")
  return sig.raw[:siglen.value]

# Verify Signature
def verify_signature(message: bytes, sig_bytes: bytes, pk_bytes: bytes) -> bytes:
  print("[VERIFY] Verifying signature...")
  pk = ctypes.create_string_buffer(pk_bytes)
  sig = ctypes.create_string_buffer(sig_bytes)
  msglen = len(message)
  siglen = len(sig_bytes)
  res = lib.verify_signature(sig, siglen, message, msglen, pk)
  return res == 0
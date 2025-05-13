import ctypes
import os

# load compiled DLL
DLL_PATH = os.path.join(os.path.dirname(__file__), '../pqclean_wrappers/kyber/pqkem.dll')
lib = ctypes.CDLL(os.path.abspath(DLL_PATH))


# Def bufffer sizes
CRYPTO_PUBLICKEYBYTES = 1568
CRYPTO_SECRETKEYBYTES = 3168
CRYPTO_CIPHERTEXTBYTES = 1568
CRYPTO_BYTES = 32

# DEf Keypair generation
def gen_keypair():
  print("[KEYPAIR] Generating ML-KEM-1024 keypair...")
  pk = ctypes.create_string_buffer(CRYPTO_PUBLICKEYBYTES)
  sk = ctypes.create_string_buffer(CRYPTO_SECRETKEYBYTES)
  res = lib.kem_keypair(pk, sk)
  if res != 0:
    raise RuntimeError("Kyber keypair generation failed")
  return pk.raw, sk.raw

# Encapsulate
def encapsulate(pk_bytes) -> bytes:
  print("[ENCAPSULATE] Encapsulating public key...")
  pk = ctypes.create_string_buffer(pk_bytes, CRYPTO_PUBLICKEYBYTES)
  ct = ctypes.create_string_buffer(CRYPTO_CIPHERTEXTBYTES)
  ss_enc = ctypes.create_string_buffer(CRYPTO_BYTES)
  res = lib.kem_enc(ct, ss_enc, pk)
  if res != 0:
    raise RuntimeError("Kyber encapsulation failed")

  return ct.raw, ss_enc.raw

# Decapsulate
def decapsulate (ct_bytes, sk_bytes):
  print("[ENCAPSULATE] Decapsulating public key...")
  sk = ctypes.create_string_buffer(sk_bytes, CRYPTO_SECRETKEYBYTES)
  ct = ctypes.create_string_buffer(ct_bytes, CRYPTO_CIPHERTEXTBYTES)
  ss_dec = ctypes.create_string_buffer(CRYPTO_BYTES)
  res = lib.kem_dec(ss_dec, ct, sk)
  if res != 0:
    raise RuntimeError("Decapsulation failed")
  # print("Decapsulation done.")
  return ss_dec.raw

import ctypes
import os

# load compiled DLL
lib = ctypes.CDLL(os.path.abspath("pqkem.dll"))

# Def bufffer sizes
CRYPTO_PUBLICKEYBYTES = 1568
CRYPTO_SECRETKEYBYTES = 3168
CRYPTO_CIPHERTEXTBYTES = 1568
CRYPTO_BYTES = 32

# Alloc buffers
pk = ctypes.create_string_buffer(CRYPTO_PUBLICKEYBYTES)
sk = ctypes.create_string_buffer(CRYPTO_SECRETKEYBYTES)
ct = ctypes.create_string_buffer(CRYPTO_CIPHERTEXTBYTES)
ss_enc = ctypes.create_string_buffer(CRYPTO_BYTES)
ss_dec = ctypes.create_string_buffer(CRYPTO_BYTES)

# Call Keypair generation
res = lib.kem_keypair(pk, sk)
assert res == 0, "Keypair generation failed"
print("Keypair generated.")

# Encapsulate
res = lib.kem_enc(ct, ss_enc, pk)
assert res == 0, "Encapsulation failed"
print("Encapsulation done.")

# Decapsulate
res = lib.kem_dec(ss_dec, ct, sk)
assert res == 0, "Decapsulation failed"
print("Decapsulation done.")

# Check if shared secrets match
print("Shared secret match:", ss_enc.raw == ss_dec.raw)
if ss_enc.raw != ss_dec.raw:
  print("Something went wrong")
else:
  print("Secure key agreement successful.")
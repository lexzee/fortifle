import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# Def qkd key simulation
def sim_qkd_key(length=32):
  print("[QKD] Simulating QKD key...")
  return os.urandom(length)

# Def hybrid key derivation
def derive_hyrid_key(kyber_ss: bytes, qkd_key: bytes, salt: bytes = None):
  print("[HKDF] Deriving AES key...")
  """Derive 256-bit AES key from Kyber & QKD using HKDF-SHA256"""
  if salt is None:
    salt = os.urandom(16) #128-bt salt

  # Comb Kyber + QKD secrets
  combo = kyber_ss + qkd_key

  hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32, # 32 bytes = 256-bit AES key
    salt=salt,
    info=b"hybrid-key-deriv",
    backend=default_backend()
  )

  aes_key = hkdf.derive(combo)
  return aes_key, salt
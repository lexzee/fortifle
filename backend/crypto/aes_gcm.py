from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_aes_gcm(key: bytes, plaintext: bytes, aad: dict) -> dict:
  print("[ENCRYPT] Encrypting data...")
  aesgcm = AESGCM(key)

  # Generate Initilisation VEctor (IV) of 96-bit
  iv = os.urandom(12)

  # Generate Associated Authenticated Data (AAD)
  aad_bytes = f"{aad.get('user_id')}|{aad.get('timestamp')}".encode()

  # Encrypt
  ct = aesgcm.encrypt(iv, plaintext, aad_bytes)
  ciphertext = ct[:-16]
  tag = ct[-16:]

  return {
    "ciphertext": ciphertext,
    "tag": tag,
    "iv": iv,
    "aad": aad_bytes
  }

def decrypt_aes_gcm(key: bytes, ciphertext: bytes, tag: bytes, iv: bytes, aad_bytes: bytes) -> bytes:
  print("[ENCRYPT] Decrypting data...")
  aesgcm = AESGCM(key)
  try:
    ct = ciphertext + tag
    plaintext = aesgcm.decrypt(iv, ct, aad_bytes)
    return plaintext
  except Exception:
    raise ValueError("Authentication failed or data is corrupted.")
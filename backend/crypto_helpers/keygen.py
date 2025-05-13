import base64
from crypto.kyber import gen_keypair
from crypto.mldsa import gen_keypair as sign_keypair
from crypto.key_agreement import sim_qkd_key, derive_hyrid_key


def kem_keypair_gen():
  # Generate keypair
    pk, sk = gen_keypair()

    pk_b64 = base64.b64encode(pk).decode()
    sk_b64 = base64.b64encode(sk).decode()

    return {
      "public_key": pk_b64,
      "secret_key": sk_b64,
      "algorithm": "ML-KEM-1024"
    }

def sign_keypair_gen():
  # Generate keypair
    pk, sk = sign_keypair()

    pk_b64 = base64.b64encode(pk).decode()
    sk_b64 = base64.b64encode(sk).decode()

    return {
      "public_key": pk_b64,
      "secret_key": sk_b64,
      "algorithm": "ML-DSA-65"
    }

def derive_aes():
  keypair = kem_keypair_gen()
  sk = base64.b64decode(keypair["secret_key"])

  # Simulate QKD key
  qkd = sim_qkd_key()

  # Derive AES_256 key
  aes_key, salt = derive_hyrid_key(sk, qkd)

  return {
    "aes_key": base64.b64encode(aes_key).decode(),
    "salt": base64.b64encode(salt).decode(),
    "qkd_key": base64.b64encode(qkd).decode()
  }


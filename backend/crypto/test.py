import base64

# Import wrappers
from kyber import gen_keypair as kyber_keypair, encapsulate, decapsulate
from mldsa import gen_keypair as mldsa_keypair, sign_message, verify_signature
from key_agreement import sim_qkd_key, derive_hyrid_key
from aes_gcm import encrypt_aes_gcm, decrypt_aes_gcm

key = ""

def test_kyber():
    print("\n🧪 Testing Kyber (ML-KEM-1024)...")

    # Key Generation
    pk, sk = kyber_keypair()
    print("✅ Kyber keypair generated.")

    # Encapsulation
    ct, ss_enc = encapsulate(pk)
    print("✅ Shared secret encapsulated.")

    # Decapsulation
    ss_dec = decapsulate(ct, sk)
    print("✅ Shared secret decapsulated.")

    # Assert match
    assert ss_enc == ss_dec, "❌ Kyber shared secrets do NOT match!"
    print("✅ Shared secrets match.\n🔐 Kyber test passed.")


def test_mldsa():
    print("\n🧪 Testing ML-DSA-65...")

    # Key Generation
    pk, sk = mldsa_keypair()
    print("✅ ML-DSA keypair generated.")

    # Sign
    message = b"This message is post-quantum signed."
    sig = sign_message(message, sk)
    print("✅ Message signed.")

    # Verify
    assert verify_signature(message, sig, pk), "❌ Signature verification failed!"
    print("✅ Signature verified.\n✍️ ML-DSA test passed.")


def test_hkdf():
    print("\n🧪 Testing Hybrid Key Derivation...")

    # Kyber Key exchange
    pk, sk = kyber_keypair()
    ct, ss_enc = encapsulate(pk)
    ss_dec = decapsulate(ct, sk)

    assert ss_enc == ss_dec, "❌ Kyber shared secrets mismatch!"

    # Simulate QKD
    qkd = sim_qkd_key()
    print("🔑 QKD key generated.")

    # Derive AES-256 key
    aes_key, salt = derive_hyrid_key(ss_enc, qkd)
    global key
    key = aes_key
    print("✅ AES Key (base64):", base64.b64encode(aes_key).decode())
    print("✅ Salt (base64):", base64.b64encode(salt).decode())

    assert len(aes_key) == 32, "❌ AES key is not 256 bits!"
    print("🎉 Hybrid key derivation test passed.")


def test_aes_gcm():
    global key
    print("\n🧪 Testing AES-256-GCM encryption...")

    key = key

    # Data
    plaintext = b"Post-Quantum AES encryption with authenticated AAD."
    aad = {
        "user_id": "bran",
        "timestamp": "2025-04-25T16:00:00Z"
    }

    # Encrypt
    result = encrypt_aes_gcm(key, plaintext, aad)
    print("✅ Encrypted:", base64.b64encode(result['ciphertext']).decode())

    # Decrypt
    decrypted = decrypt_aes_gcm(key, result["ciphertext"], result["tag"], result["iv"], result["aad"])

    assert decrypted == plaintext, "❌ AES-GCM decryption failed!"
    print("✅ AES-GCM decryption successful.")
    print(f"Decrypted = {decrypted.decode()}")


if __name__ == "__main__":
    print("🔧 Running Crypto Test Suite...\n" + "=" * 40)
    try:
        test_kyber()
        test_mldsa()
        test_hkdf()
        test_aes_gcm()
        print("\n🎉 All crypto tests passed successfully.")
    except AssertionError as e:
        print(str(e))
        print("💥 Test failed.")
    except Exception as e:
        print("🚨 Unexpected error:", str(e))

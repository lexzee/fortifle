import json.scanner
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from crypto.kyber import encapsulate, decapsulate
from crypto.key_agreement import sim_qkd_key, derive_hyrid_key
from crypto.aes_gcm import encrypt_aes_gcm, decrypt_aes_gcm
from crypto.mldsa import sign_message, verify_signature
from crypto_helpers.keygen import kem_keypair_gen, sign_keypair_gen, derive_aes
from storage.local_storage import upload_file_locally as upload_file, UPLOAD_DIR
import base64, os, io, json, time, hashlib
from datetime import datetime

from flask_jwt_extended import JWTManager, get_jwt_identity, jwt_required
from routes.auth import auth_bp, google_bp

from models.user import create_user, verify_user, test_mongo_connection, users_collection
from models.metadata import save_file_metadata, get_user_files, meta_collection
from config import SECRET_KEY

app = Flask(__name__)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  #To be removed in production
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024 * 1024
app.secret_key = SECRET_KEY
app.config["JWT_SECRET_KEY"] = SECRET_KEY
jwt = JWTManager(app)

app.register_blueprint(auth_bp, url_prefix = "/auth")
app.register_blueprint(google_bp, url_prefix = "/auth")


def fix_base64_padding(b64_string):
    return b64_string + '=' * (-len(b64_string) % 4)


@app.route('/')
def home():
  return jsonify({"success": True, "message": "Encryption Tool Backend Running!"})


# Register
# @POST "register"
@app.route('/register', methods=['POST'])
def register():
  data = request.json
  email = data.get("email")
  name = data.get("name")
  password = data.get("password")

  if not email or not password or not name:
    return jsonify({"success": False, "error": "Missing email, name or password"}), 400

  sucess, msg = create_user(email, name, password)
  if not sucess:
    return jsonify({"success": False, "error": msg}), 400

  return jsonify({"success": True, "message": msg}), 201

# Login
# @POST "login"
@app.route('/login', methods=['POST'])
def login():
  data = request.json
  email = data.get("email")
  password = data.get("password")

  if not email or not password:
    return jsonify({"success": False, "error": "Missing email or password"}), 400

  sucess, result = verify_user(email, password)
  if not sucess:
    return jsonify({"success": False, "error": result}), 401

  return jsonify({"success": True, "message": "Login successful", "user_id": str(result["_id"])}), 200

# Generate Kyber Keypairs
# @GET "/kem/keypair"
@app.route('/kem/keypair', methods=['GET'])
def kem_keypair():
  try:
    # Generate keypair
    data = kem_keypair_gen()
    return jsonify(data), 200

  except Exception as e:
    return jsonify({"error": str(e)}), 500


# Generate ML-DSA Keypairs
# @GET "/sign/keypair"
@app.route('/sign/keypair', methods=['GET'])
def sign_keypair_route():
  try:
    # Generate keypair
    data = sign_keypair_gen()
    return jsonify(data), 200

  except Exception as e:
    return jsonify({"error": str(e)}), 500


# Encapsulate
# @POST "/kem/encapsulate"
@app.route('/kem/encapsulate', methods=["POST"])
def kem_encapsulate():
  try:
    data = request.get_json()

    if not data or 'public_key' not in data:
      return jsonify({'error': "Missing 'public_key' field"}), 400

    # Decode base64 pubkey
    pk = base64.b64decode(data['public_key'])

    # Encapsulate
    ct, ss_enc = encapsulate(pk)

    return jsonify({
      "ciphertext": base64.b64encode(ct).decode(),
      "shared_secret": base64.b64encode(ss_enc).decode()
    }), 200

  except Exception as e:
    return jsonify({"error": str(e)}), 500


# Decapsulate
# @POST "/kem/decapsulate"
@app.route('/kem/decapsulate', methods=["POST"])
def kem_decapsulate():
  try:
    data = request.get_json()

    if not data or 'secret_key' not in data:
      return jsonify({'error': "Missing 'secret_key' field"}), 400
    if not data or 'ciphertext' not in data:
      return jsonify({'error': "Missing 'ciphertext' field"}), 400

    # Decode data
    ct = base64.b64decode(data["ciphertext"])
    sk = base64.b64decode(data["secret_key"])

    # Decapsulate
    ss_dec = decapsulate(ct, sk)

    return jsonify({
      "shared_secret": base64.b64encode(ss_dec).decode()
    }), 200

  except Exception as e:
    return jsonify({"error": str(e)}), 500


# Derive key using HKDF with QKD
# @POST "/derive-key"
@app.route('/derive-key', methods=["POST"])
def derive_key():
  try:
    res = derive_aes()

    return jsonify(res), 200

  except Exception as e:
    return jsonify({"error": str(e)}), 500


# Encrypt
# @POST "/encrypt"
@app.route('/encrypt', methods=['POST'])
def encrypt():
  try:
    data = request.get_json()
    aes_key = base64.b64decode(data["aes_key"])
    plaintext = base64.b64decode(data["plaintext"])
    aad = data['aad']

    # Encrypt
    encrypted = encrypt_aes_gcm(aes_key, plaintext, aad)

    return jsonify({
        "ciphertext": base64.b64encode(encrypted['ciphertext']).decode(),
        "tag": base64.b64encode(encrypted['tag']).decode(),
        "iv": base64.b64encode(encrypted['iv']).decode(),
        "aad": base64.b64encode(encrypted['aad']).decode()
    })

  except Exception as e:
    return jsonify({"error": str(e)}), 500


# Decrypt
# @POST "/decrypt"
@app.route('/decrypt', methods=['POST'])
def decrypt():
  try:
    data = request.get_json()
    aes_key = base64.b64decode(data['aes_key'])
    ciphertext = base64.b64decode(data['ciphertext'])
    tag = base64.b64decode(data['tag'])
    iv = base64.b64decode(data['iv'])
    aad = base64.b64decode(data['aad'])

    plaintext = decrypt_aes_gcm(aes_key, ciphertext, tag, iv, aad)

    return jsonify({
        "plaintext": base64.b64encode(plaintext).decode()
    })

  except Exception as e:
    return jsonify({"error": str(e)}), 500


# Sign
# @POST "/sign"
@app.route('/sign', methods=['POST'])
def sign():
  try:
    data = request.get_json()
    message = base64.b64decode(data['message'])
    sk = base64.b64decode(data['secret_key'])

    signature = sign_message(message, sk)

    return jsonify({
        "signature": base64.b64encode(signature).decode()
    }), 200

  except Exception as e:
    return jsonify({"error": str(e)}), 500


# Verify signature
# @POST "/verify"
@app.route('/verify', methods=['POST'])
def verify():
  try:
    data = request.get_json()
    message = base64.b64decode(data['message'])
    signature = base64.b64decode(data['signature'])
    pk = base64.b64decode(data['public_key'])

    valid = verify_signature(message, signature, pk)

    return jsonify({
        "valid": valid
    }), 200

  except Exception as e:
    return jsonify({"error": str(e)}), 500


# Upload file
# @POST "/secure-upload"
@app.route('/secure-upload', methods=['POST'])
def secure_upload():
  start_time = time.time()
  print(f"Starting upload: {time.ctime()}")
  try:
    user_id = request.form.get("user_id")
    file = request.files.get('file')
    sign_keypairs = sign_keypair_gen()
    sk_b64 = sign_keypairs["secret_key"]
    pk_b64 = sign_keypairs["public_key"]

    gen_aes = derive_aes()
    aes_key_b64 = gen_aes["aes_key"]

    if not file or not aes_key_b64 or not sk_b64 or not pk_b64 or not user_id:
      return jsonify({"success": False, "error": "Missing file, AES key, secret key, public key, or user id"}), 400

    plaintext = file.read()
    aes_key = base64.b64decode(aes_key_b64)
    sk = base64.b64decode(sk_b64)

    # Encrypt file
    aad = {"user_id": user_id, "timestamp": datetime.now() }
    enc_start = time.time()
    print(f"\nStarting Encryption: {time.ctime()}")
    encrypted = encrypt_aes_gcm(aes_key, plaintext, aad)

    enc_end = time.time()
    dur = enc_end - enc_start
    print(f"Encryption finished. Time: {time.ctime()} Duration: {dur}\n")

    # Sign cipher text
    signature = sign_message(encrypted["ciphertext"], sk)

    # Save encrypted file
    base_filename = os.path.splitext(file.filename)[0]
    enc_filename = f"{base_filename}.enc"
    sig_filename = f"{base_filename}.sig"
    meta_filename = f"{base_filename}.meta.json"

    meta = {
      "iv": base64.b64encode(encrypted['iv']).decode(),
      "tag": base64.b64encode(encrypted['tag']).decode(),
      "aad": base64.b64encode(encrypted['aad']).decode(),
      "public_key": pk_b64,
      "original_filename": file.filename
    }


    enc_path = upload_file(encrypted['ciphertext'], enc_filename)
    sig_path = upload_file(signature, sig_filename)
    meta_path = upload_file(json.dumps(meta).encode(), meta_filename)

    db_meta = {
      "user_id": user_id,
      "file_name": file.filename,
      "storage_paths": {
        "enc": enc_filename,
        "sig": sig_filename,
        "meta": meta_filename
      },
      "timestamp": datetime.now(),
      "encrpted": True,
      "aes_key": aes_key_b64
    }

    save_file_metadata(db_meta)

    end_time = time.time()
    dur = end_time - start_time
    print(f"Upload finished. Time: {time.ctime()} Duration: {dur}")

    return jsonify({"success": True, "data":{
        "encrypted_file_path": enc_path,
        "signature_file_path": sig_path,
        "meta_data_file_path": meta_path,
    }}), 200

  except Exception as e:
    end_time = time.time()
    dur = end_time - start_time
    print(f"Upload failed. Time: {dur}")
    return jsonify({"error": str(e)}), 500


# Download file
# @POST "/secure-download"
@app.route('/secure-download', methods=["POST"])
def secure_download():
  try:
    data = request.get_json()
    base = data.get('base')
    ext = data.get("ext")
    filename = base + "." + ext
    user_id = data.get("user_id")

    meta = meta_collection.find_one({"file_name": filename, "user_id": user_id})
    if not meta:
      return jsonify({"success": False, "error": "Metadata not found"}), 404
    aes_key_b64 = meta["aes_key"]

    if not base or not aes_key_b64:
      return jsonify({"sucesss": False, "error": "Missing filename or AES key"}), 400

    # Decode all inputs
    aes_key = base64.b64decode(fix_base64_padding(aes_key_b64))

    # Load files
    enc_path = os.path.join(UPLOAD_DIR, f"{base}.enc")
    sig_path = os.path.join(UPLOAD_DIR, f"{base}.sig")
    meta_path = os.path.join(UPLOAD_DIR, f"{base}.meta.json")

    if not os.path.exists(enc_path) or not os.path.exists(sig_path) or not os.path.exists(meta_path):
      return jsonify({"error": "File, signature or metadata not found"}), 404

    with open(enc_path, 'rb') as file:
      ciphertext = file.read()
    with open(sig_path, 'rb') as file:
      signature = file.read()
    with open(meta_path, 'r') as file:
      meta = json.load(file)

    iv = base64.b64decode(meta['iv'])
    tag = base64.b64decode(meta['tag'])
    aad = base64.b64decode(meta['aad'])
    public_key = base64.b64decode(meta['public_key'])
    original_filename = meta.get("original_filename", "decrypted_file")

    # Verify signature
    if not verify_signature(ciphertext, signature, public_key):
      return jsonify({"success": False,"error": "Signature verification failed!"}), 400

    # Decrypt file
    dec_start = time.time()
    print(f"\nStarting decryption: {time.ctime()}")
    plaintext = decrypt_aes_gcm(aes_key, ciphertext, tag, iv, aad)
    dec_end = time.time()
    dur = dec_end - dec_start
    print(f"Decryption finished : {time.ctime()}, Duration: {dur}\n")


    # Return encoded plaintxt
    # return jsonify({
    #   "success": True,
    #   "plaintext": base64.b64encode(plaintext).decode()
    # }), 200

    return send_file(
      io.BytesIO(plaintext),
      as_attachment=True,
      download_name=original_filename,
      mimetype='application/octet-stream'
    )

  except Exception as e:
    return jsonify({"success": False,"error": str(e)}), 500


# Get files
# @GET "/files"
@app.route("/files", methods=["GET"])
@jwt_required()
def get_files():
  user_id = get_jwt_identity()
  if not user_id:
    return jsonify({
      "success": False,
      "error": "unable to get userID"
    }), 401

  files = get_user_files(user_id)

  return jsonify({
    "success": True,
    "files": files
  }), 200

if __name__== '__main__':
  test_mongo_connection()
  app.run(debug=True)
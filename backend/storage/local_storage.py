import os

UPLOAD_DIR = "uploads/"

def upload_file_locally(file_bytes: bytes, filename: str) -> str:
  os.makedirs(UPLOAD_DIR, exist_ok=True)
  # chunk_size = 4096
  chunk_size = 4096
  file_path = os.path.join(UPLOAD_DIR, filename)

  with open(file_path, 'wb') as f:
  # for i in range(0, len(file_bytes), chunk_size):
  #   chunk = file_bytes[i:i + chunk_size]
  #   if not chunk:
  #     break
    f.write(file_bytes)
  #   print(f"Writing chunk: {i}")

  return file_path


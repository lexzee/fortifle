from google.cloud import storage

client = storage.Client.from_service_account_json(".\fortifile-keyfile.json")
bucket = client.get_bucket("encrypted-files")

def upload_to_cloud(bucket, source_file_name, destination_blob):
  blob = bucket.blob(source_file_name)

  gen_match_precondition = 0

  blob.upload_from_filename(source_file_name, if_generation_match=gen_match_precondition)

  print(f"File ")
import math
from pathlib import Path
import yaml

from auth.token_verify import verify_access_token
from storage.s3_client import upload_bytes

CHUNK_SIZE = 1024 * 1024  # 1MB blocks

def load_config():
    # load project config
    with Path("config/config.yaml").open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def main():
    cfg = load_config()
    region = cfg["aws"]["region"]
    raw_bucket = cfg["s3"]["raw_bucket"]

    access_token = input("Paste Cognito ACCESS token: ").strip()
    user = verify_access_token(access_token)  # fail if token bad
    user_id = user["Username"]               # cognito user id
    print("Token OK for user:", user_id)

    file_path = input("Path to file: ").strip()
    p = Path(file_path)
    data = p.read_bytes()  # read whole file

    total = len(data)
    num_chunks = math.ceil(total / CHUNK_SIZE)
    print(f"Uploading {p.name} in {num_chunks} chunks...")

    for i in range(num_chunks):
        start = i * CHUNK_SIZE
        end = min(start + CHUNK_SIZE, total)
        chunk = data[start:end]  # split file
        key = f"raw/{userid}/{p.name}/block{i:05d}"  # unique path
        upload_bytes(raw_bucket, key, chunk, region)
        print("Uploaded", key, f"({len(chunk)} bytes)")

    print("Done.")

if name == "main":
    main()  # run script

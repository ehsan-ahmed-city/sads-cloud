import math
from pathlib import Path
import yaml
import json

from auth.authenticate import authenticate_user
from metadata.validate import validate_block_meta
from storage.s3_client import upload_bytes
from encryption.salsa20_encrypt import salsa20_encrypt
from datetime import datetime, timezone
from getpass import getpass
from auth.token_verify import verify_access_token
from trust_centre.accessLogs import append_access_log
from compression.lzmaCodec import compress_bytes


CHUNK_SIZE = 1024 * 1024 # 1MB blocks

def load_config():
    with Path("config/config.yaml").open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def main():
    print("== upload_file starting ==")

    cfg = load_config()
    region = cfg["aws"]["region"]
    raw_bucket = cfg["s3"]["raw_bucket"]
    print("Bucket:", raw_bucket, "| Region:", region)

    mode = input("Auth mode (token/password): ").strip().lower()

    if mode == "token":
        access_token = input("Paste Cognito ACCESS token: ").strip().split()[0]
        user = verify_access_token(access_token)  #raise if invalid
        user_id = user["Username"]
        print("Token OK for user:", user_id)
    else:
        email = input("Email: ").strip()
        password = getpass("Password (hidden): ")
        auth = authenticate_user(email, password)  #login + trustcentre log
        user_id = auth.user_id
        print("Auth OK for user:", user_id, "| login:", auth.login_ts_utc)


    file_path = input("Path to file: ").strip()
    p = Path(file_path)
    print("Resolved path:", p.resolve())

    if not p.exists():
        raise FileNotFoundError(f"File not found: {p.resolve()}")

    data = p.read_bytes()
    total = len(data)
    print("Bytes read:", total)

    if total == 0:
        print("File empty. Nothing to upload.")
        return

    salsa_key = b"0123456789abcdef0123456789abcdef"  # 32 bytes dev key

    num_chunks = math.ceil(total / CHUNK_SIZE)
    print(f"Uploading {p.name} in {num_chunks} chunks...")

    for i in range(num_chunks):
        start = i * CHUNK_SIZE
        end = min(start + CHUNK_SIZE, total)
        chunk = data[start:end]

        #compress before encryption
        compressed = compress_bytes(chunk)

        nonce, encrypted = salsa20_encrypt(salsa_key, compressed)
        payload = nonce + encrypted  #nonce(8 bytes)+ cyphertext


        enc_s3_key = f"encrypted/{user_id}/{p.name}/block_{i:05d}"

        try:
            upload_bytes(raw_bucket, enc_s3_key, payload, region)
            print("Uploaded", enc_s3_key, f"({len(payload)} bytes)")#meta data upload terminl

            append_access_log(
                bucket=raw_bucket,
                region=region,
                user_id=user_id,
                action="upload",
                s3_key=enc_s3_key,
                ok=True,
                extra={"bytes": len(payload), "filename": p.name, "chunk_index": i},
            )

        except Exception as e:
            append_access_log(
                bucket=raw_bucket,
                region=region,
                user_id=user_id,
                action="upload",
                s3_key=enc_s3_key,
                ok=False,
                reason=str(e),
                extra={"filename": p.name, "chunk_index": i},
            )
            raise
        meta = {
            "block_id": f"block_{i:05d}",
            "owner": user_id,
            "filename": p.name,
            "chunk_index": i,
            "chunk_size": len(payload),
            "original_size": len(chunk),
            "compressed_size": len(compressed),
            "created_ts_utc": datetime.now(timezone.utc).isoformat(),
            "encrypted": True,
            "compression": "lzma",
            "cluster_id": None,
            "s3_key": enc_s3_key
        }
        validate_block_meta(meta)


        meta_key = enc_s3_key + ".meta.json"
        try:
            upload_bytes(raw_bucket, meta_key, json.dumps(meta).encode("utf-8"), region, content_type="application/json")
            print("Uploaded", meta_key)

            append_access_log(
                bucket=raw_bucket,
                region=region,
                user_id=user_id,
                action="upload_meta",
                s3_key=meta_key,
                ok=True,
                extra={"filename": p.name, "chunk_index": i},
            )
        except Exception as e:
            append_access_log(
                bucket=raw_bucket,
                region=region,
                user_id=user_id,
                action="upload_meta",
                s3_key=meta_key,
                ok=False,
                reason=str(e),
                extra={"filename": p.name, "chunk_index": i},
            )
            raise


    print("Done.")

if __name__ == "__main__":
    main()

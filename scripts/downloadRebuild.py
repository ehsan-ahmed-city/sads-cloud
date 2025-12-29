import math
from pathlib import Path
import yaml
import json
import boto3
from Crypto.Cipher import Salsa20

from compression.lzmaCodec import decompress_bytes  #only when meta says lzma

CHUNK_SIZE = 1024 * 1024 #must match upload

def load_config():
    return yaml.safe_load(Path("config/config.yaml").read_text(encoding="utf-8"))

def main():
    cfg = load_config()
    region = cfg["aws"]["region"]
    bucket = cfg["s3"]["raw_bucket"]

    user_id = input("Cognito user id: ").strip()
    filename = input("Filename (e.g. 4kphoto1.jpg): ").strip()

    salsa_key = b"0123456789abcdef0123456789abcdef"#same as upload
    s3 = boto3.client("s3", region_name=region)

    #list all block objects for this file
    prefix = f"encrypted/{user_id}/{filename}/block_"
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    keys = sorted([o["Key"] for o in resp.get("Contents", []) if "/block_" in o["Key"] and not o["Key"].endswith(".meta.json")])#blocks back together

    if not keys:
        raise RuntimeError(f"No blocks found under {prefix}")

    out_path = Path("tmp_decrypted_" + filename)
    out_path.write_bytes(b"")#ouput resets

    for key in keys:
        #try read meta for block
        meta_key = key + ".meta.json"
        compression = "none"
        try:
            meta_obj = s3.get_object(Bucket=bucket, Key=meta_key)
            meta = json.loads(meta_obj["Body"].read().decode("utf-8"))
            compression = meta.get("compression", "none")
        except Exception:
            pass

        obj = s3.get_object(Bucket=bucket, Key=key)
        payload = obj["Body"].read()

        nonce = payload[:8]
        ciphertext = payload[8:]

        cipher = Salsa20.new(key=salsa_key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)

        if compression == "lzma":
            plaintext = decompress_bytes(plaintext)

        with out_path.open("ab") as f:
            f.write(plaintext)

        print("Wrote block:", key, "| compression:", compression)

    print("Rebuilt file:", out_path)

if __name__ == "__main__":
    main()

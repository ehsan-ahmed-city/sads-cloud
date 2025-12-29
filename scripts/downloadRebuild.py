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

    # user_id = input("Cognito user id: ").strip()
    # filename = input("Filename (e.g. 4kphoto1.jpg): ").strip()
    mode = input("Auth mode (token/password): ").strip().lower()

    if mode == "token":
        access_token = input("Paste Cognito ACCESS token: ").strip().split()[0]
        user = verify_access_token(access_token)  # raises if invalid
        user_id = user["Username"]
        print("Token OK for user:", user_id)
    else:
        email = input("Email: ").strip()
        password = getpass("Password (hidden): ")
        auth = authenticate_user(email, password)
        user_id = auth.user_id
        print("Auth OK for user:", user_id, "| login:", auth.login_ts_utc)

    filename = input("Filename (e.g. README.md): ").strip()

    salsa_key = b"0123456789abcdef0123456789abcdef"#same as upload
    s3 = boto3.client("s3", region_name=region)

    #list all block objects for file
    prefix = f"encrypted/{user_id}/{filename}/block_"
    keys = []#empty lst for all s3 object keys across every page
    token = None #first page
    while True:#while loop until no mopr pages
        kwargs = {"Bucket": bucket, "Prefix": prefix}#keyword args for list object with the bycket and prefix for keys
        if token:
            
            kwargs["ContinuationToken"] = token#s3 gives token for next pagfe but don't need for first loop
        
        resp = s3.list_objects_v2(**kwargs)
        #s3 objects lists objects

        keys.extend(
            o["Key"] for o in resp.get("Contents", [])
            #takes they key after last /  for filename from path
            if o["Key"].rsplit("/", 1)[-1].startswith("block_") and not o["Key"].endswith(".meta.json")
            #"block" bit so block files are filtered and no meta json files and then appens to list
        )
        if resp.get("IsTruncated"):#if loop if more than 1000 keys for nesxt page
            token = resp.get("NextContinuationToken")
        else:
            break

    keys = sorted(keys)#keys sorted after loop


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

from pathlib import Path
import yaml
import boto3
from Crypto.Cipher import Salsa20

def load_config():
    return yaml.safe_load(Path("config/config.yaml").read_text(encoding="utf-8"))

def main():
    cfg = load_config()
    region = cfg["aws"]["region"]
    bucket = cfg["s3"]["raw_bucket"]

    user_id = input("Cognito user id: ").strip()
    filename = input("Filename (e.g. README.md): ").strip()

    salsa_key = b"0123456789abcdef0123456789abcdef"  # same key as upload

    key = f"encrypted/{user_id}/{filename}/block_00000"
    s3 = boto3.client("s3", region_name=region)

    obj = s3.get_object(Bucket=bucket, Key=key)
    payload = obj["Body"].read()

    nonce = payload[:8]
    ciphertext = payload[8:]

    cipher = Salsa20.new(key=salsa_key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)

    out = Path("tmp_decrypted_" + filename)
    out.write_bytes(plaintext)
    print("Wrote:", out)

if __name__ == "__main__":
    main()

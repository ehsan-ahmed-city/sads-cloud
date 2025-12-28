from pathlib import Path
import yaml
import boto3
from Crypto.Cipher import Salsa20
from trust_centre.accessLogs import append_access_log
from compression.lzmaCodec import decompress_bytes

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

    try:
        #get_object returns a streaming body
        obj = s3.get_object(Bucket=bucket, Key=key) #for big objects read() pulls all into memory
        payload = obj["Body"].read()

        append_access_log( #an audit trail regardless of whether caller is legit
            bucket=bucket,
            region=region,
            user_id=user_id,
            action="download",
            s3_key=key,
            ok=True,
        )

    except Exception as e:#;ogging raw exception str for debug
        append_access_log(
            bucket=bucket,
            region=region,
            user_id=user_id,
            action="download",
            s3_key=key,
            ok=False,
            reason=str(e),
        )
        raise

    nonce = payload[:8]#8byte nonce to match payload
    ciphertext = payload[8:]

    try:
        cipher = Salsa20.new(key=salsa_key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        decompressed = decompress_bytes(plaintext) #for decrompession

        out = Path("tmp_decrypted_" + filename)
        out.write_bytes(decompressed)
        print("Wrote:", out)

        append_access_log(#separate decrypt log event
            bucket=bucket,
            region=region,
            user_id=user_id,
            action="decrypt",
            s3_key=key,
            ok=True,
            extra={"output": str(out)},
        )
    except Exception as e:
        append_access_log(
            bucket=bucket,
            region=region,
            user_id=user_id,
            action="decrypt",
            s3_key=key,
            ok=False,
            reason=str(e),
        )
        raise

if __name__ == "__main__":
    main()

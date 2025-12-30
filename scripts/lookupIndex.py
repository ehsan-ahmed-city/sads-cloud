from pathlib import Path
import json
import yaml


from storage.s3_client import download_bytes
from indexing.fractalIndex import FitIndex, lookup


def load_config():
    """
    Load configuration AWS and S3
    """
    return yaml.safe_load(
        Path("config/config.yaml").read_text(encoding="utf-8")
    )


def main():
    cfg = load_config#loading config again
    region = cfg["aws"]["region"]
    bucket = cfg["s3"]["raw_bucket"]

    
    user_id = input("User id (Cognito Username): ").strip()
    fit_key = f"index/{user_id}/fit.json"#cognito username determines which index namespace to use

    raw = download_bytes(bucket, fit_key, region)#download FIT index from S3


    fit = FitIndex.from_dict(json.loads(raw.decode("utf-8")))    #rescreate FIT object from JSON
    filename = input("Filename (blank for any): ").strip() or None
    cluster_id = input(
        "Cluster id (e.g. noise, cluster_000) (blank for any): " # filter but blank is "match any"
    ).strip() or None

    keys = lookup(
    #indexed lookup returns S3 object keys for encrypted blocks that match
        fit,
        filename=filename,
        cluster_id=cluster_id
    )


    print("\n--- Lookup results ---")
    print("count:", len(keys))    #for loop for displaying it
    for k in keys:
        print(k)


if __name__ == "__main__":
    main()
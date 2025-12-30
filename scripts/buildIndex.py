from pathlib import Path
import json
import yaml
from storage.s3_client import download_bytes, upload_bytes #S3 helpers for reading/writing objects

from indexing.fractalIndex import buildFitClustSummary
#forgot to import fractal index tree builder lol


def load_config():
    #config file w AWS region and S3 bucket names

    return yaml.safe_load(
        Path("config/config.yaml").read_text(encoding="utf-8")
    )


def main():
    cfg = load_config()
    region = cfg["aws"]["region"]
    bucket = cfg["s3"]["raw_bucket"]

    user_id = input("user ID (cogni username): ").strip()#cognito id inp


    scope = input("cluster summary scope (all/filename): ").strip()
    if not scope:    #controls whether index is built for all files or specific filename subfolder
        scope = "all"


    clusters_key = f"clusters/{user_id}/{scope}/clusters.json" #DBSCAN clustering output location in S3
    print("Reading:", clusters_key)

    raw = download_bytes(bucket, clusters_key, region)#download cluster summary JSON from S3
    cluster_summary = json.loads(raw.decode("utf-8"))
    fit = buildFitClustSummary(cluster_summary)
    #build FIT from cluster summary

    
    fit_key = f"index/{user_id}/fit.json"#destination key for the index


    upload_bytes(
        #FIT structure upload to S3
        bucket=bucket,
        key=fit_key,
        data=json.dumps(fit.to_dict(), indent=2).encode("utf-8"),
        region=region,
        content_type="application/json",
    )


    print("Wrote FIT index:", fit_key)
    print("Files indexed:", list(fit.to_dict()["files"].keys()))


if __name__ == "__main__":
    main()
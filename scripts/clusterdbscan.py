from __future__ import annotations
from pathlib import Path
import json
import yaml

from sklearn.cluster import DBSCAN

from storage.s3_client import list_keys, download_bytes, upload_bytes
from metadata.validate import validate_block_meta

def load_config():
    return yaml.safe_load(Path("config/config.yaml").read_text(encoding="utf-8"))

def main():
    cfg = load_config()
    region = cfg["aws"]["region"]
    bucket = cfg["s3"]["raw_bucket"]

    user_id = input("Cognito user id: ").strip()
    filename = input("Filename (blank = all): ").strip()

    if filename:
        prefix = f"encrypted/{user_id}/{filename}/"
        cluster_out_prefix = f"clusters/{user_id}/{filename}/"
    else:
        prefix = f"encrypted/{user_id}/"
        cluster_out_prefix = f"clusters/{user_id}/all/"

    #1 list metadata keys
    all_keys = list_keys(bucket, prefix, region)
    meta_keys = [k for k in all_keys if k.endswith(".meta.json")]

    if not meta_keys:
        print("No metadata found under:", prefix)
        return

    #2 download+ parse metadata
    metas: list[dict] = []
    for k in meta_keys:
        raw = download_bytes(bucket, k, region)
        meta = json.loads(raw.decode("utf-8"))
        metas.append(meta)

    X = [[m["compressed_size"]] for m in metas]#clusters with compresion and storage behaviour like paper



    model = DBSCAN(eps=200_000, min_samples=2)#DBSCAN eps is in "bytes" 
    labels = model.fit_predict(X)


    clusters: dict[str, list[str]] = {}#6 assign cluster_id and upload updated metadata
    updated = 0

    for meta, label, meta_key in zip(metas, labels, meta_keys):
        # DBSCAN uses -1 for noise/outliers
        cluster_id = "noise" if label == -1 else f"cluster_{label:03d}"
        meta["cluster_id"] = cluster_id

        #keep schema valid
        validate_block_meta(meta)

        upload_bytes(#write updated meta back to same key
            bucket=bucket,
            key=meta_key,
            data=json.dumps(meta).encode("utf-8"),
            region=region,
            content_type="application/json",
        )
        updated += 1

        clusters.setdefault(cluster_id, []).append(meta["s3_key"])

    summary = {#cluster summary    
        "user_id": user_id,
        "filename": filename if filename else None,
        "prefix_scanned": prefix,
        "total_blocks": len(metas),
        "clusters": clusters,
    }

    out_key = cluster_out_prefix + "clusters.json"
    upload_bytes(
        bucket=bucket,
        key=out_key,
        data=json.dumps(summary, indent=2).encode("utf-8"),
        region=region,
        content_type="application/json",
    )

    print("Updated metadata files:", updated)
    print("Wrote cluster summary:", out_key)
    print("Cluster counts:", {k: len(v) for k, v in clusters.items()})

if __name__ == "__main__":
    main()
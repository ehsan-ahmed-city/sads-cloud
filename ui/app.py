import math
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from auth.token_verify import verify_access_token
from storage.s3_client import upload_bytes, download_bytes, list_keys

from trust_centre.accessLogs import append_access_log
from encryption.salsa20_encrypt import salsa20_encrypt

import streamlit as st
import yaml
import boto3
from Crypto.Cipher import Salsa20
from sklearn.cluster import DBSCAN

from compression.lzmaCodec import compress_bytes, decompress_bytes


from indexing.fractalIndex import build_fit_from_cluster_summary, FitIndex, lookup#indexing renamed file

CHUNK_SIZE = 1024 * 1024
SALSA_KEY = b"0123456789abcdef0123456789abcdef" #dev key like in scripts


def load_config():
    return yaml.safe_load(Path("config/config.yaml").read_text(encoding="utf-8"))


def try_validate_meta(meta: dict) -> None:#validate meta if validator exists otherwise skip
    try:
        from metadata.validate import validate_block_meta
        validate_block_meta(meta)
    except Exception:
        pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def s3_client(region: str):
    return boto3.client("s3", region_name=region)


def decrypt_payload(payload: bytes) -> bytes:
    nonce = payload[:8]
    ciphertext = payload[8:]
    cipher = Salsa20.new(key=SALSA_KEY, nonce=nonce)
    return cipher.decrypt(ciphertext)


def upload_file_bytes(*, bucket: str, region: str, user_id: str, filename: str, data: bytes):
    total = len(data)
    num_chunks = math.ceil(total / CHUNK_SIZE)

    for i in range(num_chunks):
        start = i * CHUNK_SIZE
        end = min(start + CHUNK_SIZE, total)
        chunk = data[start:end]

        compressed = compress_bytes(chunk)
        nonce, encrypted = salsa20_encrypt(SALSA_KEY, compressed)
        payload = nonce + encrypted

        enc_s3_key = f"encrypted/{user_id}/{filename}/block_{i:05d}"

        upload_bytes(bucket, enc_s3_key, payload, region)
        append_access_log(
            bucket=bucket,
            region=region,
            user_id=user_id,
            action="upload",
            s3_key=enc_s3_key,
            ok=True,
            extra={"bytes": len(payload), "filename": filename, "chunk_index": i},
        )

        meta = {
            "block_id": f"block_{i:05d}",
            "owner": user_id,
            "filename": filename,
            "chunk_index": i,
            "chunk_size": len(payload),
            "original_size": len(chunk),
            "compressed_size": len(compressed),
            "created_ts_utc": datetime.now(timezone.utc).isoformat(),
            "encrypted": True,
            "compression": "lzma",
            "cluster_id": None,
            "s3_key": enc_s3_key,
        }
        try_validate_meta(meta)

        meta_key = enc_s3_key + ".meta.json"
        upload_bytes(bucket, meta_key, json.dumps(meta).encode("utf-8"), region, content_type="application/json")
        append_access_log(
            bucket=bucket,
            region=region,
            user_id=user_id,
            action="upload_meta",
            s3_key=meta_key,
            ok=True,
            extra={"filename": filename, "chunk_index": i},
        )

    return num_chunks


def cluster_dbscan(*, bucket: str, region: str, user_id: str, filename: str | None):
    if filename:
        prefix = f"encrypted/{user_id}/{filename}/"
        out_prefix = f"clusters/{user_id}/{filename}/"
    else:
        prefix = f"encrypted/{user_id}/"
        out_prefix = f"clusters/{user_id}/all/"

    all_keys = list_keys(bucket, prefix, region)
    meta_keys = [k for k in all_keys if k.endswith(".meta.json")]
    if not meta_keys:
        return None

    metas = []
    for mk in meta_keys:
        raw = download_bytes(bucket, mk, region)
        metas.append(json.loads(raw.decode("utf-8")))

    # Prefer compressed_size; fallback to chunk_size for safety
    X = [[m.get("compressed_size", m.get("chunk_size"))] for m in metas]

    model = DBSCAN(eps=200_000, min_samples=2)
    labels = model.fit_predict(X)

    clusters: dict[str, list[str]] = {}
    updated = 0
    for meta, label, meta_key in zip(metas, labels, meta_keys):
        cluster_id = "noise" if label == -1 else f"cluster_{label:03d}"
        meta["cluster_id"] = cluster_id
        try_validate_meta(meta)

        upload_bytes(
            bucket=bucket,
            key=meta_key,
            data=json.dumps(meta).encode("utf-8"),
            region=region,
            content_type="application/json",
        )
        updated += 1
        clusters.setdefault(cluster_id, []).append(meta["s3_key"])

    summary = {
        "user_id": user_id,
        "filename": filename if filename else None,
        "prefix_scanned": prefix,
        "total_blocks": len(metas),
        "clusters": clusters,
    }

    out_key = out_prefix + "clusters.json"
    upload_bytes(
        bucket=bucket,
        key=out_key,
        data=json.dumps(summary, indent=2).encode("utf-8"),
        region=region,
        content_type="application/json",
    )

    append_access_log(
        bucket=bucket,
        region=region,
        user_id=user_id,
        action="cluster",
        s3_key=out_key,
        ok=True,
        extra={"updated_metas": updated, "total_blocks": len(metas)},
    )

    return out_key, summary


def build_index(*, bucket: str, region: str, clusters_summary: dict):
    fit = build_fit_from_cluster_summary(clusters_summary)
    fit_key = f"index/{fit.user_id}/fit.json"
    upload_bytes(
        bucket=bucket,
        key=fit_key,
        data=json.dumps(fit.to_dict(), indent=2).encode("utf-8"),
        region=region,
        content_type="application/json",
    )
    return fit_key


def load_fit(*, bucket: str, region: str, user_id: str) -> FitIndex:
    fit_key = f"index/{user_id}/fit.json"
    raw = download_bytes(bucket, fit_key, region)
    return FitIndex.from_dict(json.loads(raw.decode("utf-8")))


def rebuild_from_keys(*, bucket: str, region: str, keys: list[str]) -> bytes:
    s3 = s3_client(region)
    out = bytearray()

    for key in keys:
        meta_key = key + ".meta.json"
        compression = "none"
        try:
            meta_obj = s3.get_object(Bucket=bucket, Key=meta_key)
            meta = json.loads(meta_obj["Body"].read().decode("utf-8"))
            compression = meta.get("compression", "none")
        except Exception:
            pass

        payload = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        plaintext = decrypt_payload(payload)

        if compression == "lzma":
            plaintext = decompress_bytes(plaintext)

        out.extend(plaintext)

    return bytes(out)



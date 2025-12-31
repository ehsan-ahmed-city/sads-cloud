import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


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


from indexing.fractalIndex import buildFitClustSummary, FitIndex, lookup#indexing renamed file

CHUNK_SIZE = 1024 * 1024
SALSA_KEY = b"0123456789abcdef0123456789abcdef"#dev key like in scripts


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

    X = [[m.get("compressed_size", m.get("chunk_size"))] for m in metas] #compressed_size; fallback to chunk size for safety

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


st.set_page_config(page_title="SADS-Cloud Demo Console", layout="wide")
st.title("SADS-Cloud Demo Console")

cfg = load_config()
region = cfg["aws"]["region"]
bucket = cfg["s3"]["raw_bucket"]

#session state
st.session_state.setdefault("access_token", "")
st.session_state.setdefault("user_id", "")
st.session_state.setdefault("last_clusters_key", "")
st.session_state.setdefault("last_clusters_summary", None)
st.session_state.setdefault("last_fit_key", "")

colA, colB = st.columns(2)
with colA:
    st.write(f"**Bucket:** {bucket}")
with colB:
    st.write(f"**Region:** {region}")

st.divider()

tabs = st.tabs(["1) Auth", "2) Upload", "3) Cluster", "4) Build Index", "5) Lookup", "6) Retrieve & Verify"])

# 1) Auth
with tabs[0]:
    st.subheader("Auth (Cognito token verify)")
    token = st.text_area("Paste Cognito ACCESS token", value=st.session_state["access_token"], height=120)
    if st.button("Verify token"):
        try:
            user = verify_access_token(token.strip().split()[0])
            st.session_state["access_token"] = token.strip()
            st.session_state["user_id"] = user["Username"]
            st.success(f"Token OK for user: {st.session_state['user_id']}")
        except Exception as e:
            st.error(str(e))

# 2) Upload
with tabs[1]:
    st.subheader("Upload (split -> LZMA -> SALSA20 -> S3)")#uploadFile.py command
    if not st.session_state["user_id"]:
        st.warning("verify token first in the auth tab")
    up = st.file_uploader("choose a file to upload", type=None)
    if up and st.button("uplaod file"):
        data = up.read()
        filename = up.name
        user_id = st.session_state["user_id"]
        try:
            n = upload_file_bytes(bucket=bucket, region=region, user_id=user_id, filename=filename, data=data)
            st.success(f"Uploaded {filename} in {n} blocks")
        except Exception as e:
            st.error(str(e))

# 3) Cluster
with tabs[2]:#cluster
    st.subheader("DBSCAN clustering metadata to clusters.json)")
    if not st.session_state["user_id"]:
        st.warning("Verify token first in the Auth tab.")
    fname = st.text_input("Filename (blank = all)", value="")
    if st.button("Run clustering"):
        try:
            out = cluster_dbscan(bucket=bucket, region=region, user_id=st.session_state["user_id"], filename=fname or None)
            if not out:
                st.warning("No metadata to clutser")
            else:
                out_key, summary = out
                st.session_state["last_clusters_key"] = out_key
                st.session_state["last_clusters_summary"] = summary
                st.success(f"Wrote: {out_key}")
                st.json(summary)
        except Exception as e:
            st.error(str(e))

# 4) Build Index
with tabs[3]:
    st.subheader("Build FIT index (clusters.json -> index/<user>/fit.json)")
    if not st.session_state["user_id"]:
        st.warning("Verify token first in the Auth tab.")
    if st.button("Build index from last cluster summary"):
        if not st.session_state["last_clusters_summary"]:
            st.warning("Run clustering first (Cluster tab).")
        else:
            try:
                fit_key = build_index(bucket=bucket, region=region, clusters_summary=st.session_state["last_clusters_summary"])
                st.session_state["last_fit_key"] = fit_key
                st.success(f"Wrote FIT index: {fit_key}")
            except Exception as e:
                st.error(str(e))

# 5) Lookup
with tabs[4]:
    st.subheader("lokup in FIT index")
    if not st.session_state["user_id"]:
        st.warning("verify token first in the Auth tab")
    filename = st.text_input("Filename", value="")
    cluster_id = st.text_input("Cluster id (e.g. noise, cluster_000, blank = any)", value="")
    if st.button("Lookup"):
        try:
            fit = load_fit(bucket=bucket, region=region, user_id=st.session_state["user_id"])
            keys = lookup(fit, filename=filename or None, cluster_id=cluster_id or None)
            st.write(f"**count:** {len(keys)}")
            st.code("\n".join(keys))
        except Exception as e:
            st.error(str(e))

# 6) Retrieve & Verify
with tabs[5]:
    st.subheader("retreive (indexed) -> decrypt -> decompress -> rebuild -> SHA256 verify")

    filename = st.text_input("Filename to rebuild", value="")
    use_index = st.checkbox("use index", value=True)
    cluster_id = st.text_input("Cluster id for rebulid (blank =all)", value="")

    if st.button("Rebuild file"):
        try:
            user_id = st.session_state["user_id"]
            if not user_id:
                st.warning("Verify token first.")
                st.stop()

            if use_index:
                fit = load_fit(bucket=bucket, region=region, user_id=user_id)
                keys = lookup(fit, filename=filename or None, cluster_id=cluster_id or None)
            else:
                prefix = f"encrypted/{user_id}/{filename}/block_"
                allk = list_keys(bucket, prefix, region)
                keys = sorted([k for k in allk if k.rsplit("/", 1)[-1].startswith("block_") and not k.endswith(".meta.json")])

            if not keys:
                st.error("No keys found for rebuild.")
                st.stop()

            rebuilt = rebuild_from_keys(bucket=bucket, region=region, keys=keys)
            rebuilt_hash = sha256_bytes(rebuilt)

            st.success(f"Rebuilt {len(keys)} blocks. SHA256: {rebuilt_hash}")
            st.download_button("Download rebuilt file", data=rebuilt, file_name=f"tmp_decrypted_{filename}")


            local_path = Path("data") / filename #compare to local original if present
            if local_path.exists():
                orig_hash = sha256_file(local_path)
                st.write(f"Original SHA256: {orig_hash}")
                st.write(f"Match: {orig_hash == rebuilt_hash}")
        except Exception as e:
            st.error(str(e))

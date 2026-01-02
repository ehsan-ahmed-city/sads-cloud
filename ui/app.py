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
import os
import time

from compression.lzmaCodec import compress_bytes, decompress_bytes
from auth.authenticate import authenticate_user#added import since it wouldn't give option to sing in for access token


from indexing.fractalIndex import buildFitClustSummary, FitIndex, lookup#indexing renamed file

CHUNK_SIZE = 1024 * 1024
SALSA_KEY = b"0123456789abcdef0123456789abcdef"#dev key like in scripts just for demo


#helper functions

def load_config():
    return yaml.safe_load(Path("config/config.yaml").read_text(encoding="utf-8"))


def try_validate_meta(meta: dict) -> None:#validate meta if validator exists otherwise skip
    try:
        from metadata.validate import validate_block_meta
        validate_block_meta(meta)
    except Exception:
        pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()#for integrity and shows no artifacts


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):#streaming file into hash so largw files not loaded in memory
            h.update(chunk)
    return h.hexdigest().upper()


def s3_client(region: str):
    return boto3.client("s3", region_name=region)


def decrypt_payload(payload: bytes) -> bytes:
    #salsa 20 uses 8 byte nonce in Pycryptodome
    nonce = payload[:8]
    ciphertext = payload[8:]
    cipher = Salsa20.new(key=SALSA_KEY, nonce=nonce)
    return cipher.decrypt(ciphertext)

def emr_client(region: str): #emr helpers
    return boto3.client("emr-serverless", region_name=region) #serverless API client

def start_emr_encrypt_job(
    *,
    region: str,
    app_id: str,
    exec_role_arn: str,
    code_bucket: str,
    code_key: str,
    in_bucket: str,
    in_key: str,
    out_bucket: str,
    user_id: str,
    filename: str,
    salsaKeyHex: str,
):
    """^starts a spark job in emr serverless by pointing it at entrypoint in s3, 
    the params are environment variables so both drivers can read them"""

    entry = f"s3://{code_bucket}/{code_key}"


    deps_whl = f"s3://{code_bucket}/emr/deps/pycryptodome-3.20.0-cp35-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
    confs = (
        f"--conf spark.executorEnv.SADS_REGION={region} "
        f"--conf spark.executorEnv.SADS_IN_BUCKET={in_bucket} "
        f"--conf spark.executorEnv.SADS_IN_KEY={in_key} "
        f"--conf spark.executorEnv.SADS_OUT_BUCKET={out_bucket} "
        f"--conf spark.executorEnv.SADS_USER_ID={user_id} "
        f"--conf spark.executorEnv.SADS_FILENAME={filename} "
        f"--conf spark.executorEnv.SADS_SALSA_KEY_HEX={salsaKeyHex} "
        f"--conf spark.emr-serverless.driverEnv.SADS_REGION={region} "
        f"--conf spark.emr-serverless.driverEnv.SADS_IN_BUCKET={in_bucket} "
        f"--conf spark.emr-serverless.driverEnv.SADS_IN_KEY={in_key} "
        f"--conf spark.emr-serverless.driverEnv.SADS_OUT_BUCKET={out_bucket} "
        f"--conf spark.emr-serverless.driverEnv.SADS_USER_ID={user_id} "
        f"--conf spark.emr-serverless.driverEnv.SADS_FILENAME={filename} "
        f"--conf spark.emr-serverless.driverEnv.SADS_SALSA_KEY_HEX={salsaKeyHex}"
    )


    spark_params = f"--py-files {deps_whl} " + confs#executors can importp ycryptodome

    emr = emr_client(region)

    resp = emr.start_job_run(
        applicationId=app_id,
        executionRoleArn=exec_role_arn,
        jobDriver={
            "sparkSubmit": {
                "entryPoint": entry, #the script location in s3
                "sparkSubmitParameters": spark_params,
            }
        },
        configurationOverrides={
            "monitoringConfiguration": {

                "s3MonitoringConfiguration": {"logUri": f"s3://{out_bucket}/emr-logs/"} # emr logs to s3
            }
        },
    )
    return resp["jobRunId"]

def get_emr_job_status(*, region: str, app_id: str, job_run_id: str) -> dict:
    #gtes the job state and metadata
    emr = emr_client(region)
    resp = emr.get_job_run(applicationId=app_id, jobRunId=job_run_id)
    return resp["jobRun"]


def upload_file_bytes(*, bucket: str, region: str, user_id: str, filename: str, data: bytes):
    """ It splits into blocks then we compress eahc block with LZMA  and then we encrypt each compressed block with salsa20
    and the payload and metadata is uploaded to the s3 bucket"""
    total = len(data)
    num_chunks = math.ceil(total / CHUNK_SIZE)

    for i in range(num_chunks):
        start = i * CHUNK_SIZE
        end = min(start + CHUNK_SIZE, total)
        chunk = data[start:end]

        compressed = compress_bytes(chunk)
        nonce, encrypted = salsa20_encrypt(SALSA_KEY, compressed)
        payload = nonce + encrypted #stored nonce and ciphertext

        enc_s3_key = f"encrypted/{user_id}/{filename}/block_{i:05d}"

        upload_bytes(bucket, enc_s3_key, payload, region)
        append_access_log(
            #event is appended to the access log
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

#function reads metadata and json file and cluster blocks bsed on size

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


    X = [[m.get("compressed_size", m.get("chunk_size"))] for m in metas] #compressed_size fallback to chunk size

    model = DBSCAN(eps=200_000, min_samples=2)
    labels = model.fit_predict(X)
    clusters: dict[str, list[str]] = {}
    updated = 0
    for meta, label, meta_key in zip(metas, labels, meta_keys):
        #^for loop to update each metadata file with cluster assignment
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

    return out_key, summary #cluster json summary to s3 and update meta


def build_index(*, bucket: str, region: str, clusters_summary: dict):
    #^function to cluster json summary to fractal tree index for quick lookup

    fit = buildFitClustSummary(clusters_summary)
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
    return FitIndex.from_dict(json.loads(raw.decode("utf-8"))) #function returns fractal index tree into memory from s3


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
            #reads each block object
        except Exception:
            pass

        payload = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        plaintext = decrypt_payload(payload) #decrypts and meta is shown

        if compression == "lzma":#if check for LZMA and it decompresses if match
            plaintext = decompress_bytes(plaintext)

        out.extend(plaintext) #in order of keys passed in

    return bytes(out)

# streamlit UI
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
#values stay the same in reruns like when a button is pressed

colA, colB = st.columns(2)
with colA:
    st.write(f"**Bucket:** {bucket}")
with colB:
    st.write(f"**Region:** {region}")

st.divider()

tabs = st.tabs(["1) Auth", "2) Upload", "3) EMR Batch encryp", "4) Cluster ", "5) Build Index", "6) Lookup", "7) Retrieve and Verify"])

# 1) Auth
with tabs[0]:
    st.subheader("Auth (Cognito sign in or token verify)")

    SIGNIN = "Sign in (email + password)"
    PASTE = "Paste access token"
    mode = st.radio("Auth mode", [SIGNIN, PASTE], horizontal=True)

    if mode == SIGNIN:
        email = st.text_input("Email", key="auth_email")
        password = st.text_input("Password", type="password", key="auth_password")

        if st.button("Sign in", key="btn_signin"):
            try:
                auth = authenticate_user(email, password)


                token = getattr(auth, "access_token", None) or getattr(auth, "AccessToken", None) #adapts to whatever authenticate_user returns
                if not token and isinstance(auth, dict):
                    token = auth.get("access_token") or auth.get("AccessToken")

                if not token:
                    st.error("authenticate_user() didn't return an access token.")
                    st.stop()

                user = verify_access_token(token)
                st.session_state["access_token"] = token
                st.session_state["user_id"] = user["Username"]

                st.success(f"Signed in. User: {st.session_state['user_id']}")
                st.code(st.session_state["access_token"])

            except Exception as e:
                st.error(str(e))

    else:
        token = st.text_area(
            "enter your cognito access token",
            value=st.session_state.get("access_token", ""),
            height=120,
            key="auth_token_text",
        )

        if st.button("Verify token", key="btn_verify"):
            try:
                tok = token.strip().split()[0]
                user = verify_access_token(tok)
                st.session_state["access_token"] = tok
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
    
    if up and st.button("upload file"):
        data = up.read()
        filename = up.name
        user_id = st.session_state["user_id"]
        try:
            n = upload_file_bytes(bucket=bucket, region=region, user_id=user_id, filename=filename, data=data)
            st.success(f"Uploaded {filename} in {n} blocks")
        except Exception as e:
            st.error(str(e))

# 3) Cluster
with tabs[3]:#cluster
    st.subheader("DBSCAN clustering metadata to clusters.json)")
    if not st.session_state["user_id"]:
        st.warning("Verify token first in the Auth tab.")#prevents access if not logged in
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
with tabs[4]:
    st.subheader("Build FIT index (clusters.json -> index/<user>/fit.json)")
    if not st.session_state["user_id"]:
        st.warning("Verify token first in the Auth tab.")#prevents access if not logged in
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

with tabs[5]:# 5)lookup
    st.subheader("lokup in FIT index")
    if not st.session_state["user_id"]:#prevents access if not logged in
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

# 6) Retrieve and Verify
with tabs[5]:
    st.subheader("retreive (indexed) -> decrypt -> decompress -> rebuild -> SHA256 verify")

    filename = st.text_input("Filename to rebuild", value="")
    use_index = st.checkbox("use index", value=True)
    cluster_id = st.text_input("Cluster id for rebulid (blank =all)", value="")

    if st.button("Rebuild file"):
        try:
            user_id = st.session_state["user_id"]
            if not user_id:
                st.warning("Verify token first.")#prevents access if not logged in
                st.stop()

            if use_index:
                #pulls the needed blocks quickly by FIT index
                
                fit = load_fit(bucket=bucket, region=region, user_id=user_id)
                keys = lookup(fit, filename=filename or None, cluster_id=cluster_id or None)
            else:
                prefix = f"encrypted/{user_id}/{filename}/block_"
                allk = list_keys(bucket, prefix, region)
                #going through all blocks and sorting
                keys = sorted([k for k in allk if k.rsplit("/", 1)[-1].startswith("block_") and not k.endswith(".meta.json")])

            if not keys:
                st.error("No keys found for rebuild.")
                st.stop()

            rebuilt = rebuild_from_keys(bucket=bucket, region=region, keys=keys)
            rebuilt_hash = sha256_bytes(rebuilt)

            append_access_log( # didn't have rebuild in aws access log in s3
                bucket=bucket,
                region=region,
                user_id=user_id,
                action="rebuild",
                s3_key=f"encrypted/{user_id}/{filename}/",
                ok=True,
                extra={
                    "blocks": len(keys),
                    "sha256": rebuilt_hash,
                    "used_index": use_index,
                    "cluster_id": cluster_id or "all",
                },
            )


            st.success(f"Rebuilt {len(keys)} blocks. SHA256: {rebuilt_hash}")
            st.download_button("Download rebuilt file", data=rebuilt, file_name=f"tmp_decrypted_{filename}")


            local_path = Path("data") / filename #compare to local original if present
            if local_path.exists():
                orig_hash = sha256_file(local_path)
                st.write(f"Original SHA256: {orig_hash}")
                st.write(f"Match: {orig_hash == rebuilt_hash}")
        except Exception as e:
            st.error(str(e))

with tabs[2]: #emr 
    st.subheader("EMR serverless batch job, encrypt/upload in AWS")

    st.caption("runs the EMR Serverless job and shows status and where logs in S3 are")

    #defaults saves last used emr fields
    st.session_state.setdefault("emr_app_id", "")
    st.session_state.setdefault("emr_exec_role_arn", "")
    st.session_state.setdefault("emr_code_bucket", bucket)  #default to raw bucket
    
    st.session_state.setdefault("emr_code_key", "emr/encryptUpload.py")#forgot to include lol
    
    st.session_state.setdefault("emr_job_run_id", "")
    st.session_state.setdefault("emr_last_status", "")

    app_id = st.text_input("EMR Serverless Application ID", value=st.session_state["emr_app_id"])
    exec_role_arn = st.text_input("Execution Role ARN", value=st.session_state["emr_exec_role_arn"])
    code_bucket = st.text_input("Code bucket", value=st.session_state["emr_code_bucket"])
    code_key = st.text_input("Code key (script path in S3)", value=st.session_state["emr_code_key"])
    #^input controls to keep values persistent

    st.divider()

    st.subheader("Upload RAW file for EMR input")

    raw_up = st.file_uploader("Choose RAW file (EMR enc)", key="raw_uploader")

    if raw_up and st.button("Upload RAW to S3"):
        if not st.session_state.get("user_id"):
            st.error("sign in first so we can store under your user id")
        else:
            user_id = st.session_state["user_id"]
            raw_key = f"raw/{user_id}/{raw_up.name}"
            data = raw_up.read()

            try:
                upload_bytes(bucket=bucket, key=raw_key, data=data, region=region)
                st.success("RAW uploaded.")
                st.code(raw_key)
            except Exception as e:
                st.error(str(e))
    

    st.divider()   
    in_bucket = st.text_input("Input bucket", value=bucket)
    in_key = st.text_input("Input key (object in S3)", value="")#existing one in s3 that spark will process
    out_bucket = st.text_input("Output bucket", value=bucket)

    # Salsa key hex for b"0123456789abcdef0123456789abcdef"
    default_salsa_hex = "3031323334353637383961626364656630313233343536373839616263646566"
    salsaKeyHex = st.text_input("Salsa key hex (64 chars)", value=default_salsa_hex)

    # Use the signed-in user_id if available
    user_id = st.session_state.get("user_id", "") or st.text_input("User ID (Cognito Username)", value="")
    filename = st.text_input("Filename label ", value="README.md")

    cols = st.columns(3)
    with cols[0]:
        if st.button("start EMR job"):
            if not (app_id and exec_role_arn and code_bucket and code_key and in_bucket and in_key and out_bucket and user_id and filename):
                st.error("enter all fields")
            else:
                try:
                    job_run_id = start_emr_encrypt_job(
                        region=region,
                        app_id=app_id,
                        exec_role_arn=exec_role_arn,
                        code_bucket=code_bucket,
                        code_key=code_key,
                        in_bucket=in_bucket,
                        in_key=in_key,
                        out_bucket=out_bucket,
                        user_id=user_id,
                        filename=filename,
                        salsaKeyHex=salsaKeyHex,
                    )

                    
                    st.session_state["emr_app_id"] = app_id#inputs are saved so doesn't need to be netered in rerun if using same vals
                    st.session_state["emr_exec_role_arn"] = exec_role_arn
                    st.session_state["emr_code_bucket"] = code_bucket
                    st.session_state["emr_code_key"] = code_key
                    st.session_state["emr_job_run_id"] = job_run_id
                    st.success(f"Started EMR job. jobRunId = {job_run_id}")
                except Exception as e:
                    st.error(str(e))

    with cols[1]:
        if st.button("Refresh status"):
            job_run_id = st.session_state.get("emr_job_run_id", "")
            if not job_run_id:
                st.warning("No jobRunId yet. Start a job first.")
            else:
                try:
                    job = get_emr_job_status(region=region, app_id=app_id, job_run_id=job_run_id)
                    state = job.get("state")
                    st.session_state["emr_last_status"] = state or ""
                    st.write("**State:**", state)
                    st.json(job)
                except Exception as e:
                    st.error(str(e))

    with cols[2]:
        if st.button("Wait until done (about 60secs max)"):
            job_run_id = st.session_state.get("emr_job_run_id", "")
            if not job_run_id:
                st.warning("No jobRunId yet, start a job first")
            else:
                ph = st.empty()
                try:
                    for _ in range(20):  #for loop because 20*3 = 60s
                        job = get_emr_job_status(region=region, app_id=app_id, job_run_id=job_run_id)
                        state = job.get("state")
                        ph.write(f"**State:** {state}")
                        if state in ("SUCCESS", "FAILED", "CANCELLED"):

                            break
                        time.sleep(3)
                    st.json(job)
                except Exception as e:

                    st.error(str(e))

    st.divider()
    st.subheader("where to look in S3")

    st.write("**EMR logs:**", f"s3://{out_bucket}/emr-logs/")
    st.write("**Expected outputs (like eg):**", f"s3://{out_bucket}/encrypted/{user_id}/{filename}/")

    if st.button("list output keys under encrypted/<user>/<filename>/"):
        if not user_id or not filename:
            st.warning("need to enter user_id + filename")
        else:
            prefix = f"encrypted/{user_id}/{filename}/"
            try:
                keys = list_keys(out_bucket, prefix, region)
                if not keys:
                    st.warning("No objects found yet with that prefix")
                else:
                    st.write(f"Found {len(keys)} objects:")
                    st.code("\n".join(sorted(keys)))
            except Exception as e:
                st.error(str(e))

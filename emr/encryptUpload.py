from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator, List, Tuple

import boto3
import lzma
from Crypto.Cipher import Salsa20
from pyspark.sql import SparkSession


CHUNK_SIZE = 1024 * 1024
@dataclass
class JobArgs:
    region: str
    in_bucket: str
    in_key: str
    out_bucket: str
    user_id: str
    filename: str
    salsa_key_hex: str  #64 hex chars for 32 bytes


def _get_arg(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise RuntimeError(f"Missing env var: {name}")
    return v


def load_args() -> JobArgs:
    return JobArgs(
        region=_get_arg("SADS_REGION"),
        in_bucket=_get_arg("SADS_IN_BUCKET"),
        in_key=_get_arg("SADS_IN_KEY"),
        out_bucket=_get_arg("SADS_OUT_BUCKET"),
        user_id=_get_arg("SADS_USER_ID"),
        filename=_get_arg("SADS_FILENAME"),
        salsa_key_hex=_get_arg("SADS_SALSA_KEY_HEX"),
    )


def compress_bytes(data: bytes) -> bytes:
    return lzma.compress(data)


def salsa20_encrypt(key32: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    cipher = Salsa20.new(key=key32)
    #^creates random nonce
    ciphertext = cipher.encrypt(plaintext)
    return cipher.nonce, ciphertext


def read_source_bytes(region: str, bucket: str, key: str) -> bytes:
    s3 = boto3.client("s3", region_name=region)
    obj = s3.get_object(Bucket=bucket, Key=key)

    return obj["Body"].read()


def write_partition(
    rows: Iterator[Tuple[int, bytes]],
    region: str,
    out_bucket: str,
    user_id: str,
    filename: str,
    salsa_key32: bytes,
) -> Iterator[int]:
    """
    Each row is chunk_index, chunk_bytes
    Writes teh block and meta json file and returns chunk index for progress
    """
    s3 = boto3.client("s3", region_name=region)

    for i, chunk in rows:
        compressed = compress_bytes(chunk)
        nonce, encrypted = salsa20_encrypt(salsa_key32, compressed)
        payload = nonce + encrypted

        enc_key = f"encrypted/{user_id}/{filename}/block_{i:05d}"
        meta_key = enc_key + ".meta.json"


        s3.put_object(Bucket=out_bucket, Key=enc_key, Body=payload)#the payload


        meta = {        #meta data
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
            "s3_key": enc_key,
            "source": "emr-serverless",
        }
        s3.put_object(

            Bucket=out_bucket,

            Key=meta_key,
            Body=json.dumps(meta).encode("utf-8"),
            ContentType="application/json",
        )

        yield i


def main():
    args = load_args()
    salsa_key32 = bytes.fromhex(args.salsa_key_hex)
    if len(salsa_key32) != 32:
        raise RuntimeError("SADS_SALSA_KEY_HEX must be 32 bytes (64 hex chars)")

    spark = SparkSession.builder.appName("sads-emr-encrypt-upload").getOrCreate()
    sc = spark.sparkContext

    data = read_source_bytes(args.region, args.in_bucket, args.in_key)
    total = len(data)
    if total == 0:
        print("Source file empty; nothing to do.")
        return

    num_chunks = math.ceil(total / CHUNK_SIZE)


    chunks: List[Tuple[int, bytes]] = [] #create index, bytes rows
    for i in range(num_chunks):
        start = i * CHUNK_SIZE
        end = min(start + CHUNK_SIZE, total)
        chunks.append((i, data[start:end]))

    rdd = sc.parallelize(chunks, min(num_chunks, max(1, sc.defaultParallelism)))

    written = (
        rdd.mapPartitions(
            lambda rows: write_partition(
                rows,
                region=args.region,
                out_bucket=args.out_bucket,
                user_id=args.user_id,
                filename=args.filename,
                salsa_key32=salsa_key32,
            )
        )
        .collect()
    )

    print(f"emr wrote {len(written)} blocks to s3://{args.out_bucket}/encrypted/{args.user_id}/{args.filename}/")
    #wrote to s3


if __name__ == "__main__":
    main()

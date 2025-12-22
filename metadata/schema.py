BLOCK_METADATA_SCHEMA = {
    "block_id": "string (block_00000)",
    "owner": "string (cognito username)",
    "filename": "string",
    "chunk_index": "int",
    "chunk_size": "int (bytes)",
    "created_ts_utc": "ISO8601 string",
    "encrypted": "bool",
    "compression": "string (none|lzma)",
    "cluster_id": "string|null",
    "s3_key": "string (full s3 object key)"
}

REQUIRED_FIELDS = set(BLOCK_METADATA_SCHEMA.keys())
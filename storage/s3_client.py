import boto3
from typing import Optional

def s3(region: str):
    # create s3 client
    return boto3.client("s3", region_name=region)

def upload_bytes(
    bucket: str,
    key: str,
    data: bytes,
    region: str,
    content_type: Optional[str] = None
):
    client = s3(region)  # get s3 connection
    extra = {}           # optional params
    if content_type:
        extra["ContentType"] = content_type  # set mime type
    client.put_object(
        Bucket=bucket,
        Key=key,
        Body=data,
        **extra
    )  # upload object
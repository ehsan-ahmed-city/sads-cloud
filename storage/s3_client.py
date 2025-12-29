import boto3
from typing import Optional

def s3(region: str):
    # create s3 client bound to a specific region
    return boto3.client("s3", region_name=region)

def upload_bytes(
    bucket: str,
    key: str,
    data: bytes,
    region: str,
    content_type: Optional[str] = None
):
    client = s3(region)  # get s3 connection
    extra = {}           

    if content_type:
        extra["ContentType"] = content_type


    client.put_object(
        Bucket=bucket,
        Key=key,
        Body=data,
        **extra
    )

def download_bytes(bucket: str, key: str, region: str) -> bytes:
    client = s3(region)

    # get_object returns metadata abd streaming body,not bytes directly
    obj = client.get_object(Bucket=bucket, Key=key)    #the Body is a botocore.response.StreamingBody object


    #for very large objects, need stream or chunk-read instead
    return obj["Body"].read()#.read() pulls the entire object into memory.

def list_keys(bucket: str, prefix: str, region: str) -> list[str]:
    client = s3(region)
    keys: list[str] = []
    token: Optional[str] = None #pagination token (none for first req)


    #S3 list_objects_v2 returns at most 1000 keys per request
    while True:
        #Build request parameters dynamically
        kwargs = {
            "Bucket": bucket,
            "Prefix": prefix #limits results to a logical "folder"
        }

        #ContinuationToken tells S3 where to continue listing
        if token:
            kwargs["ContinuationToken"] = token

        resp = client.list_objects_v2(**kwargs)

        #default to an empty list to avoid Keyerror if no objects match the prefix
        for item in resp.get("Contents", []):
            keys.append(item["Key"]) #only need the object key

        #if Istruncated true, more results to fetch
        if resp.get("IsTruncated"):
            token = resp.get("NextContinuationToken")
        else:
            break  #all keys listed

    return keys
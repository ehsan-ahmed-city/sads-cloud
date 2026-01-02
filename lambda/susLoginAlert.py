import json
import os
import boto3

s3 = boto3.client("s3")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["TOPIC_ARN"] #from Lambdas env vars


def lambda_handler(event, context):
    for record in event.get("Records", []):#s3 event-> bucket/key

        s3info = record.get("s3", {})
        bucket = s3info.get("bucket", {}).get("name")
        key = s3info.get("object", {}).get("key")

        if not bucket or not key:
            continue

        #gets the login log JSON and reads it
        obj = s3.get_object(Bucket=bucket, Key=key)
        body = obj["Body"].read().decode("utf-8")
        data = json.loads(body)

        decision = data.get("decision", "UNKNOWN")
        if decision != "SUSPICIOUS":

            continue #allows user to caryr on

        user_id = data.get("user_id")
        ts = data.get("ts_utc")
        reasons = data.get("reasons", [])

        features = data.get("features", {})

        msg = {
            "alert": "SUSPICIOUS_LOGIN",
            "bucket": bucket,
            "key": key,
            "user_id": user_id,
            "ts_utc": ts,
            "reasons": reasons,
            "features": features,
        }

        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject="SADS-Cloud Alert: Suspicious login detected",
            Message=json.dumps(msg, indent=2),
        )

    return {"ok": True}

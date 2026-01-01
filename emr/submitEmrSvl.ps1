param(
  [Parameter(Mandatory=$true)] [string]$AppId,
  [Parameter(Mandatory=$true)] [string]$ExecRoleArn,
  [Parameter(Mandatory=$true)] [string]$Region,
  [Parameter(Mandatory=$true)] [string]$CodeBucket,
  #^where the job file lives

  [Parameter(Mandatory=$true)] [string]$CodeKey,
   #^emr/jobs/emr_encryptUpload.py
  [Parameter(Mandatory=$true)] [string]$InBucket,
  [Parameter(Mandatory=$true)] [string]$InKey,
  [Parameter(Mandatory=$true)] [string]$OutBucket,
  [Parameter(Mandatory=$true)] [string]$UserId,
  [Parameter(Mandatory=$true)] [string]$Filename,
  [Parameter(Mandatory=$true)] [string]$SalsaKeyHex #64 hex chararacters
)

$entry = "s3://$CodeBucket/$CodeKey"

aws emr-serverless start-job-run `
  --application-id $AppId `
  --execution-role-arn $ExecRoleArn `
  --region $Region `
  --job-driver "{
    `"sparkSubmit`": {
      `"entryPoint`": `"$entry`",
      `"sparkSubmitParameters`": `"--conf spark.executorEnv.SADS_REGION=$Region --conf spark.executorEnv.SADS_IN_BUCKET=$InBucket --conf spark.executorEnv.SADS_IN_KEY=$InKey --conf spark.executorEnv.SADS_OUT_BUCKET=$OutBucket --conf spark.executorEnv.SADS_USER_ID=$UserId --conf spark.executorEnv.SADS_FILENAME=$Filename --conf spark.executorEnv.SADS_SALSA_KEY_HEX=$SalsaKeyHex`"
    }
  }" `
  --configuration-overrides "{
    `"monitoringConfiguration`": {
      `"s3MonitoringConfiguration`": { `"logUri`": `"s3://$OutBucket/emr-logs/`" }
    }
  }"

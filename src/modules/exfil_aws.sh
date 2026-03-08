#!/usr/bin/env bash
# S7aba - AWS Data Exfiltration Module

discover_data_stores() {
    log_info "Discovering AWS data stores..."

    # S3 buckets with size estimation
    local buckets
    buckets=$(aws s3api list-buckets --query 'Buckets[].Name' -o tsv 2>/dev/null)
    for bucket in $buckets; do
        local region
        region=$(aws s3api get-bucket-location --bucket "$bucket" --query 'LocationConstraint' -o text 2>/dev/null)
        log_finding "INFO" "S3 Bucket" "$bucket (region: ${region:-us-east-1})"

        # Check for public access
        local acl
        acl=$(aws s3api get-bucket-acl --bucket "$bucket" -o json 2>/dev/null)
        if echo "$acl" | jq -e '.Grants[] | select(.Grantee.URI | test("AllUsers|AuthenticatedUsers"))' &>/dev/null; then
            log_finding "HIGH" "Public S3 Bucket" "$bucket has public ACL grants"
        fi
    done

    # RDS databases
    local rds
    rds=$(aws rds describe-db-instances --query 'DBInstances[].{ID:DBInstanceIdentifier,Engine:Engine,Size:AllocatedStorage,Public:PubliclyAccessible}' -o json 2>/dev/null)
    echo "$rds" | jq -r '.[] | "\(.ID) [\(.Engine)] \(.Size)GB Public=\(.Public)"' 2>/dev/null | while read -r line; do
        log_finding "INFO" "RDS Instance" "$line"
    done

    # DynamoDB tables
    local tables
    tables=$(aws dynamodb list-tables --query 'TableNames' -o tsv 2>/dev/null)
    local table_count
    table_count=$(echo "$tables" | wc -w)
    log_finding "INFO" "DynamoDB Tables" "$table_count tables"

    # EBS snapshots (may contain sensitive data)
    local snapshots
    snapshots=$(aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[].{ID:SnapshotId,Size:VolumeSize,Desc:Description}' -o json 2>/dev/null)
    log_finding "INFO" "EBS Snapshots" "$(echo "$snapshots" | jq 'length') snapshots"

    # Elastic File Systems
    local efs
    efs=$(aws efs describe-file-systems --query 'FileSystems[].{ID:FileSystemId,Size:SizeInBytes.Value}' -o json 2>/dev/null)
    [[ -n "$efs" && "$efs" != "[]" ]] && log_finding "INFO" "EFS" "$(echo "$efs" | jq 'length') file systems"
}

classify_data() {
    log_info "Classifying data sensitivity..."

    # Sample S3 bucket contents for sensitive patterns
    local buckets
    buckets=$(aws s3api list-buckets --query 'Buckets[].Name' -o tsv 2>/dev/null)
    for bucket in $buckets; do
        local objects
        objects=$(aws s3api list-objects-v2 --bucket "$bucket" --max-items 50 \
            --query 'Contents[].Key' -o tsv 2>/dev/null)

        # Check for sensitive file patterns
        if echo "$objects" | grep -qiE '\.(sql|bak|dump|csv|xlsx|pem|key|env|conf|credentials)$'; then
            log_finding "HIGH" "Sensitive Files" "Bucket '$bucket' contains potentially sensitive file types"
        fi
        if echo "$objects" | grep -qiE '(backup|export|dump|secret|credential|password|private)'; then
            log_finding "HIGH" "Sensitive Names" "Bucket '$bucket' has objects with sensitive naming patterns"
        fi
    done
}

evaluate_exfil_channels() {
    log_info "Evaluating exfiltration channels..."

    # S3 bucket policy - can we make a bucket public?
    log_finding "INFO" "S3 Copy" "aws s3 cp/sync to external bucket or local"
    log_finding "INFO" "RDS Snapshot" "Create snapshot → share with external account"
    log_finding "INFO" "EBS Snapshot Share" "Share EBS snapshot with external account"
    log_finding "INFO" "Lambda Exfil" "Lambda function to stream data to external endpoint"
    log_finding "INFO" "DNS Exfil" "Encode data in DNS queries via Route53 or external resolver"
    log_finding "INFO" "SSM Parameter" "Store data in SSM Parameter Store for later retrieval"

    # Check if we can create S3 buckets (for staging)
    local can_create
    can_create=$(aws iam simulate-principal-policy --policy-source-arn "$(aws sts get-caller-identity --query Arn -o text)" \
        --action-names "s3:CreateBucket" --query 'EvaluationResults[0].EvalDecision' -o text 2>/dev/null)
    [[ "$can_create" == "allowed" ]] && log_finding "HIGH" "S3 Staging" "Can create S3 bucket for data staging"
}

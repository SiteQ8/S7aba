#!/usr/bin/env bash
# S7aba - AWS Reconnaissance Module

enum_identity() {
    log_info "Querying AWS STS..."
    local identity
    identity=$(aws sts get-caller-identity 2>/dev/null)

    if [[ -n "$identity" ]]; then
        local account arn user_id
        account=$(json_get "$identity" '.Account')
        arn=$(json_get "$identity" '.Arn')
        user_id=$(json_get "$identity" '.UserId')

        log_finding "INFO" "AWS Identity" "Account: $account | ARN: $arn"
        CURRENT_USER="$arn"
        CURRENT_ROLE=$(echo "$arn" | grep -oP '(?<=assumed-role/)[^/]+' || echo "direct-user")
    else
        log_error "Unable to query AWS identity. Check credentials."
    fi

    # Check for IMDS v1 (less secure)
    local imds_token
    imds_token=$(curl -s --max-time 2 -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)

    if curl -s --max-time 2 http://169.254.169.254/latest/meta-data/ &>/dev/null; then
        if [[ -z "$imds_token" ]]; then
            log_finding "HIGH" "IMDSv1 Enabled" "Instance metadata accessible without token (potential SSRF risk)"
        else
            log_finding "LOW" "IMDSv2 Enabled" "Token-based metadata access configured"
        fi
    fi
}

enum_permissions() {
    log_info "Enumerating IAM permissions..."

    # List attached policies
    local username
    username=$(aws iam get-user --query 'User.UserName' --output text 2>/dev/null)

    if [[ -n "$username" && "$username" != "None" ]]; then
        log_info "User: $username"

        # Attached policies
        local policies
        policies=$(aws iam list-attached-user-policies --user-name "$username" \
            --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null)

        for policy in $policies; do
            local name=$(echo "$policy" | grep -oP '[^/]+$')
            log_finding "INFO" "Attached Policy" "$name ($policy)"

            # Check for admin-like policies
            if [[ "$name" == *"Admin"* || "$name" == *"FullAccess"* ]]; then
                log_finding "HIGH" "Overprivileged Policy" "$name grants broad access"
            fi
        done

        # Inline policies
        local inline
        inline=$(aws iam list-user-policies --user-name "$username" \
            --query 'PolicyNames' --output text 2>/dev/null)
        for pol in $inline; do
            log_finding "MEDIUM" "Inline Policy" "$pol (inline policies bypass standard governance)"
        done

        # Group memberships
        local groups
        groups=$(aws iam list-groups-for-user --user-name "$username" \
            --query 'Groups[].GroupName' --output text 2>/dev/null)
        for group in $groups; do
            log_finding "INFO" "Group Membership" "$group"
        done
    fi
}

enum_services() {
    log_info "Discovering AWS services..."

    # S3 Buckets
    local buckets
    buckets=$(aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null)
    local bucket_count=$(echo "$buckets" | wc -w)
    log_finding "INFO" "S3 Buckets" "Found $bucket_count buckets"

    for bucket in $buckets; do
        # Check public access
        local public_block
        public_block=$(aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null)
        if [[ -z "$public_block" ]]; then
            log_finding "HIGH" "S3 Public Access" "Bucket '$bucket' may lack public access block"
        fi
    done

    # EC2 Instances
    local instances
    instances=$(aws ec2 describe-instances --query 'Reservations[].Instances[].{ID:InstanceId,State:State.Name,Type:InstanceType}' --output json 2>/dev/null)
    local inst_count=$(json_get "$instances" 'length')
    log_finding "INFO" "EC2 Instances" "Found $inst_count instances"

    # Lambda Functions
    local lambdas
    lambdas=$(aws lambda list-functions --query 'Functions[].FunctionName' --output text 2>/dev/null)
    local lambda_count=$(echo "$lambdas" | wc -w)
    log_finding "INFO" "Lambda Functions" "Found $lambda_count functions"

    # RDS Databases
    local rds
    rds=$(aws rds describe-db-instances --query 'DBInstances[].{ID:DBInstanceIdentifier,Engine:Engine,Public:PubliclyAccessible}' --output json 2>/dev/null)
    if echo "$rds" | jq -e '.[] | select(.Public==true)' &>/dev/null; then
        log_finding "HIGH" "Public RDS Instance" "Database instance is publicly accessible"
    fi
}

enum_network() {
    log_info "Analyzing network configuration..."

    # VPCs
    local vpcs
    vpcs=$(aws ec2 describe-vpcs --query 'Vpcs[].{ID:VpcId,CIDR:CidrBlock,Default:IsDefault}' --output json 2>/dev/null)
    log_finding "INFO" "VPCs" "$(json_get "$vpcs" 'length') VPCs found"

    # Security Groups with 0.0.0.0/0 ingress
    local open_sgs
    open_sgs=$(aws ec2 describe-security-groups \
        --filters "Name=ip-permission.cidr,Values=0.0.0.0/0" \
        --query 'SecurityGroups[].{ID:GroupId,Name:GroupName}' --output json 2>/dev/null)

    if [[ -n "$open_sgs" && "$open_sgs" != "[]" ]]; then
        local sg_count=$(json_get "$open_sgs" 'length')
        log_finding "HIGH" "Open Security Groups" "$sg_count SGs allow 0.0.0.0/0 ingress"
    fi
}

enum_secrets() {
    log_info "Scanning for exposed secrets..."

    # SSM Parameters
    local params
    params=$(aws ssm describe-parameters --query 'Parameters[?Type==`SecureString`].Name' --output text 2>/dev/null)
    local param_count=$(echo "$params" | wc -w)
    [[ $param_count -gt 0 ]] && log_finding "INFO" "SSM SecureStrings" "$param_count secure parameters found"

    # Secrets Manager
    local secrets
    secrets=$(aws secretsmanager list-secrets --query 'SecretList[].Name' --output text 2>/dev/null)
    local secret_count=$(echo "$secrets" | wc -w)
    [[ $secret_count -gt 0 ]] && log_finding "INFO" "Secrets Manager" "$secret_count secrets found"

    # Environment variables in Lambda
    local lambdas
    lambdas=$(aws lambda list-functions --query 'Functions[].FunctionName' --output text 2>/dev/null)
    for fn in $lambdas; do
        local env_vars
        env_vars=$(aws lambda get-function-configuration --function-name "$fn" \
            --query 'Environment.Variables' --output json 2>/dev/null)
        if echo "$env_vars" | grep -qiE '(password|secret|key|token|api_key)' 2>/dev/null; then
            log_finding "HIGH" "Lambda Secret in Env" "Function '$fn' has sensitive-looking env vars"
        fi
    done
}

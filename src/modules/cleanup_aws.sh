#!/usr/bin/env bash
# S7aba - AWS Cleanup Module

identify_artifacts() {
    log_info "Identifying S7aba artifacts in AWS..."

    # IAM users created by S7aba
    local users
    users=$(aws iam list-users --query "Users[?contains(UserName, 'svc-monitoring')].UserName" -o tsv 2>/dev/null)
    [[ -n "$users" ]] && log_finding "INFO" "Backdoor Users" "$users"

    # CloudTrail events (our activity)
    local events
    events=$(aws cloudtrail lookup-events --max-results 20 \
        --lookup-attributes AttributeKey=Username,AttributeValue="$(aws sts get-caller-identity --query 'Arn' -o text 2>/dev/null | grep -oP '[^/]+$')" \
        --query 'Events[].EventName' -o tsv 2>/dev/null)
    [[ -n "$events" ]] && log_finding "INFO" "CloudTrail Events" "$(echo "$events" | wc -w) recent events logged"

    # Lambda functions
    local lambdas
    lambdas=$(aws lambda list-functions --query "Functions[?contains(FunctionName, 's7aba')].FunctionName" -o tsv 2>/dev/null)
    [[ -n "$lambdas" ]] && log_finding "INFO" "S7aba Lambda" "$lambdas"

    # EventBridge rules
    local rules
    rules=$(aws events list-rules --query "Rules[?contains(Name, 's7aba')].Name" -o tsv 2>/dev/null)
    [[ -n "$rules" ]] && log_finding "INFO" "EventBridge Rules" "$rules"

    log_info "Review CloudTrail for complete activity log"
}

remove_artifacts() {
    log_warn "Removing S7aba artifacts..."

    # Remove backdoor users
    local users
    users=$(aws iam list-users --query "Users[?contains(UserName, 'svc-monitoring')].UserName" -o tsv 2>/dev/null)
    for user in $users; do
        log_info "Removing user: $user"
        # Delete access keys
        local keys
        keys=$(aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[].AccessKeyId' -o tsv 2>/dev/null)
        for key in $keys; do
            aws iam delete-access-key --user-name "$user" --access-key-id "$key" 2>/dev/null
        done
        # Detach policies
        local policies
        policies=$(aws iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[].PolicyArn' -o tsv 2>/dev/null)
        for pol in $policies; do
            aws iam detach-user-policy --user-name "$user" --policy-arn "$pol" 2>/dev/null
        done
        aws iam delete-user --user-name "$user" 2>/dev/null
        log_success "Removed user: $user"
    done

    # Remove Lambda functions
    local lambdas
    lambdas=$(aws lambda list-functions --query "Functions[?contains(FunctionName, 's7aba')].FunctionName" -o tsv 2>/dev/null)
    for fn in $lambdas; do
        aws lambda delete-function --function-name "$fn" 2>/dev/null
        log_success "Removed Lambda: $fn"
    done

    # Clean local logs and temp files
    rm -f /tmp/s7aba.* 2>/dev/null
    log_success "Local temp files cleaned"
}

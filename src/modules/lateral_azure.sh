#!/usr/bin/env bash
# S7aba - Azure Lateral Movement Module

map_trust_relationships() {
    log_info "Mapping Azure trust relationships..."

    # Multi-tenant app registrations
    local apps
    apps=$(az ad app list --filter "signInAudience eq 'AzureADMultipleOrgs'" \
        --query '[].{Name:displayName,AppId:appId}' -o json 2>/dev/null)
    if [[ -n "$apps" && "$apps" != "[]" ]]; then
        log_finding "MEDIUM" "Multi-Tenant Apps" "$(echo "$apps" | jq 'length') multi-tenant applications"
    fi

    # B2B guest users
    local guests
    guests=$(az ad user list --filter "userType eq 'Guest'" --query '[].displayName' -o tsv 2>/dev/null | wc -l)
    [[ $guests -gt 0 ]] && log_finding "INFO" "Guest Users" "$guests B2B guest accounts"

    # Cross-subscription access
    local subs
    subs=$(az account list --query '[].{Name:name,ID:id,Tenant:tenantId}' -o json 2>/dev/null)
    local sub_count
    sub_count=$(echo "$subs" | jq 'length')
    [[ $sub_count -gt 1 ]] && log_finding "HIGH" "Multi-Subscription" "Access to $sub_count subscriptions"

    # Managed identity assignments
    local mi_assignments
    mi_assignments=$(az role assignment list --query "[?principalType=='ServicePrincipal']" -o json 2>/dev/null | jq 'length')
    log_finding "INFO" "SP Role Assignments" "$mi_assignments service principal assignments"
}

find_pivot_points() {
    log_info "Identifying Azure pivot points..."

    # VMs with managed identities
    local vms
    vms=$(az vm list --query '[].{Name:name,RG:resourceGroup}' -o json 2>/dev/null)
    echo "$vms" | jq -r '.[] | "\(.Name)|\(.RG)"' 2>/dev/null | while IFS='|' read -r name rg; do
        local identity
        identity=$(az vm identity show --name "$name" --resource-group "$rg" 2>/dev/null)
        [[ -n "$identity" ]] && log_finding "MEDIUM" "VM Managed Identity" "VM '$name' has managed identity"
    done

    # App Service with managed identities
    local webapps
    webapps=$(az webapp list --query '[?identity!=null].{Name:name,Type:identity.type}' -o json 2>/dev/null)
    [[ -n "$webapps" && "$webapps" != "[]" ]] && log_finding "MEDIUM" "App Service MI" "$(echo "$webapps" | jq 'length') web apps with managed identity"

    # Azure DevOps service connections
    log_finding "INFO" "Check Manually" "Azure DevOps service connections (requires ADO access)"
}

enumerate_targets() {
    log_info "Enumerating Azure targets..."

    # All resource groups and resources
    local resources
    resources=$(az resource list --query '[].{Type:type,Name:name}' -o json 2>/dev/null | jq 'group_by(.Type) | map({type: .[0].Type, count: length})')
    echo "$resources" | jq -r '.[] | "\(.type): \(.count)"' 2>/dev/null | while read -r line; do
        log_finding "INFO" "Resource" "$line"
    done
}

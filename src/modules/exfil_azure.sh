#!/usr/bin/env bash
# S7aba - Azure Data Exfiltration Module

discover_data_stores() {
    log_info "Discovering Azure data stores..."

    # Storage accounts and containers
    local accounts
    accounts=$(az storage account list --query '[].{Name:name,Kind:kind,RG:resourceGroup}' -o json 2>/dev/null)
    echo "$accounts" | jq -r '.[] | "\(.Name)|\(.RG)"' 2>/dev/null | while IFS='|' read -r name rg; do
        log_finding "INFO" "Storage Account" "$name ($rg)"
        local key
        key=$(az storage account keys list --account-name "$name" --resource-group "$rg" --query '[0].value' -o tsv 2>/dev/null)
        if [[ -n "$key" ]]; then
            log_finding "HIGH" "Storage Key Access" "Can read storage keys for '$name'"
            local containers
            containers=$(az storage container list --account-name "$name" --account-key "$key" --query '[].name' -o tsv 2>/dev/null)
            for c in $containers; do
                log_finding "INFO" "Container" "$name/$c"
            done
        fi
    done

    # SQL databases
    az sql server list --query '[].{Name:name,FQDN:fullyQualifiedDomainName}' -o json 2>/dev/null | \
        jq -r '.[] | "\(.Name) → \(.FQDN)"' 2>/dev/null | while read -r line; do
        log_finding "INFO" "SQL Server" "$line"
    done

    # Cosmos DB
    local cosmos
    cosmos=$(az cosmosdb list --query '[].{Name:name,Kind:kind}' -o json 2>/dev/null)
    [[ -n "$cosmos" && "$cosmos" != "[]" ]] && log_finding "INFO" "Cosmos DB" "$(echo "$cosmos" | jq 'length') accounts"

    # Key Vault data
    local vaults
    vaults=$(az keyvault list --query '[].name' -o tsv 2>/dev/null)
    for v in $vaults; do
        log_finding "MEDIUM" "Key Vault" "$v (secrets, keys, certificates)"
    done
}

classify_data() {
    log_info "Classifying Azure data sensitivity..."
    log_finding "INFO" "Classification" "Review storage blob names for sensitive patterns"
    log_finding "INFO" "Classification" "Check SQL databases for PII/financial data schemas"
    log_finding "INFO" "Classification" "Examine Key Vault contents for credentials"
}

evaluate_exfil_channels() {
    log_info "Evaluating Azure exfiltration channels..."
    log_finding "INFO" "AzCopy" "azcopy to external storage account or SAS URL"
    log_finding "INFO" "Storage SAS" "Generate SAS tokens for external access"
    log_finding "INFO" "SQL Export" "Export database via bacpac to accessible storage"
    log_finding "INFO" "Function Exfil" "Function App to relay data externally"
    log_finding "INFO" "Disk Export" "Generate disk SAS URL for VM disk download"
    log_finding "INFO" "Logic App" "Logic App HTTP connector to send data externally"
}

#!/usr/bin/env bash
# S7aba - Azure Cleanup Module

identify_artifacts() {
    log_info "Identifying S7aba artifacts in Azure..."

    # App registrations
    local apps
    apps=$(az ad app list --filter "startswith(displayName, 'svc-monitoring')" --query '[].{Name:displayName,ID:appId}' -o json 2>/dev/null)
    [[ -n "$apps" && "$apps" != "[]" ]] && log_finding "INFO" "Backdoor Apps" "$(echo "$apps" | jq -r '.[].Name')"

    # Activity log
    local activities
    activities=$(az monitor activity-log list --max-events 20 --query '[].{Op:operationName.value,Status:status.value}' -o json 2>/dev/null)
    log_finding "INFO" "Activity Log" "$(echo "$activities" | jq 'length') recent operations"

    log_info "Review Azure Activity Log for complete audit trail"
}

remove_artifacts() {
    log_warn "Removing S7aba artifacts..."

    # Remove backdoor apps
    local apps
    apps=$(az ad app list --filter "startswith(displayName, 'svc-monitoring')" --query '[].appId' -o tsv 2>/dev/null)
    for app in $apps; do
        az ad app delete --id "$app" 2>/dev/null
        log_success "Removed app: $app"
    done

    rm -f /tmp/s7aba.* 2>/dev/null
    log_success "Local temp files cleaned"
}

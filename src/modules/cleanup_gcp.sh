#!/usr/bin/env bash
# S7aba - GCP Cleanup Module

identify_artifacts() {
    log_info "Identifying S7aba artifacts in GCP..."

    local project
    project=$(gcloud config get-value project 2>/dev/null)

    # Service accounts
    local sas
    sas=$(gcloud iam service-accounts list --filter="displayName:Monitoring" --format='value(email)' 2>/dev/null)
    [[ -n "$sas" ]] && log_finding "INFO" "Backdoor SAs" "$sas"

    # SA keys
    local sa_list
    sa_list=$(gcloud iam service-accounts list --format='value(email)' 2>/dev/null)
    for sa in $sa_list; do
        local user_keys
        user_keys=$(gcloud iam service-accounts keys list --iam-account="$sa" --managed-by=user --format='value(name)' 2>/dev/null | wc -l)
        [[ $user_keys -gt 0 ]] && log_finding "INFO" "User-Managed Keys" "$sa: $user_keys keys"
    done

    # Audit log
    log_info "Review Cloud Audit Logs: gcloud logging read 'logName:activity'"
}

remove_artifacts() {
    log_warn "Removing S7aba artifacts..."

    local project
    project=$(gcloud config get-value project 2>/dev/null)

    # Remove backdoor SAs
    local sas
    sas=$(gcloud iam service-accounts list --filter="displayName:Monitoring" --format='value(email)' 2>/dev/null)
    for sa in $sas; do
        gcloud iam service-accounts delete "$sa" --quiet 2>/dev/null
        log_success "Removed SA: $sa"
    done

    rm -f /tmp/s7aba_*.json /tmp/s7aba.* 2>/dev/null
    log_success "Local temp files cleaned"
}

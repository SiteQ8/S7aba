#!/usr/bin/env bash
# S7aba - GCP Lateral Movement Module

map_trust_relationships() {
    log_info "Mapping GCP trust relationships..."

    local project
    project=$(gcloud config get-value project 2>/dev/null)

    # Service account impersonation chains
    local sa_list
    sa_list=$(gcloud iam service-accounts list --format='value(email)' 2>/dev/null)
    for sa in $sa_list; do
        local sa_policy
        sa_policy=$(gcloud iam service-accounts get-iam-policy "$sa" --format=json 2>/dev/null)
        local impersonators
        impersonators=$(echo "$sa_policy" | jq -r '.bindings[]? | select(.role | test("serviceAccountTokenCreator|serviceAccountUser")) | .members[]' 2>/dev/null)
        [[ -n "$impersonators" ]] && log_finding "HIGH" "SA Impersonation Chain" "$sa can be impersonated by: $impersonators"
    done

    # Cross-project bindings
    local policy
    policy=$(gcloud projects get-iam-policy "$project" --format=json 2>/dev/null)
    local external
    external=$(echo "$policy" | jq -r '.bindings[].members[]' 2>/dev/null | grep -v "$project" | grep "serviceAccount:" | sort -u)
    [[ -n "$external" ]] && log_finding "HIGH" "External SA Bindings" "Cross-project service accounts in IAM policy"

    # Workload Identity Federation
    local pools
    pools=$(gcloud iam workload-identity-pools list --location=global --format='value(name)' 2>/dev/null)
    [[ -n "$pools" ]] && log_finding "INFO" "Workload Identity Federation" "External identity pools configured"

    # Domain-wide delegation
    for sa in $sa_list; do
        local sa_info
        sa_info=$(gcloud iam service-accounts describe "$sa" --format=json 2>/dev/null)
        if echo "$sa_info" | jq -e '.oauth2ClientId' &>/dev/null; then
            log_finding "MEDIUM" "Potential DWD" "SA $sa has OAuth client ID (check G Workspace delegation)"
        fi
    done
}

find_pivot_points() {
    log_info "Identifying GCP pivot points..."

    # Compute instances with service accounts
    gcloud compute instances list --format='value(name,zone,serviceAccounts[0].email)' 2>/dev/null | while read -r name zone sa; do
        [[ -n "$sa" ]] && log_finding "MEDIUM" "VM Service Account" "Instance '$name' ($zone): $sa"
    done

    # Cloud Functions with SAs
    gcloud functions list --format='value(name,serviceAccountEmail)' 2>/dev/null | while read -r name sa; do
        [[ -n "$sa" ]] && log_finding "INFO" "Function SA" "Function '$name': $sa"
    done

    # GKE clusters (pivot to K8s)
    local gke
    gke=$(gcloud container clusters list --format='value(name,location)' 2>/dev/null)
    [[ -n "$gke" ]] && log_finding "HIGH" "GKE Clusters" "Can pivot to Kubernetes via GKE"
}

enumerate_targets() {
    log_info "Enumerating GCP targets..."

    # All accessible projects
    gcloud projects list --format='value(projectId,name)' 2>/dev/null | while read -r pid pname; do
        log_finding "INFO" "Project" "$pid ($pname)"
    done

    # Organization info
    local org
    org=$(gcloud organizations list --format='value(ID,displayName)' 2>/dev/null)
    [[ -n "$org" ]] && log_finding "INFO" "Organization" "$org"
}

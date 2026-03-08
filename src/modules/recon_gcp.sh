#!/usr/bin/env bash
# S7aba - GCP Reconnaissance Module

enum_identity() {
    log_info "Querying GCP identity..."

    local account
    account=$(gcloud config get-value account 2>/dev/null)
    local project
    project=$(gcloud config get-value project 2>/dev/null)

    if [[ -n "$account" ]]; then
        log_finding "INFO" "GCP Account" "$account"
        log_finding "INFO" "Active Project" "$project"
        CURRENT_USER="$account"
    else
        log_error "No active GCP account. Run 'gcloud auth login' first."
        return 1
    fi

    # Check for metadata server (on GCE)
    local meta_email
    meta_email=$(curl -s --max-time 2 -H "Metadata-Flavor: Google" \
        "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email" 2>/dev/null)
    if [[ -n "$meta_email" ]]; then
        log_finding "HIGH" "GCE Metadata SA" "Instance service account: $meta_email"

        # Check scopes
        local scopes
        scopes=$(curl -s --max-time 2 -H "Metadata-Flavor: Google" \
            "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/scopes" 2>/dev/null)
        if echo "$scopes" | grep -q "cloud-platform"; then
            log_finding "CRITICAL" "Full Cloud Scope" "Service account has cloud-platform scope (full access)"
        fi
    fi

    # List all accessible projects
    local projects
    projects=$(gcloud projects list --format='value(projectId)' 2>/dev/null | wc -l)
    log_finding "INFO" "Accessible Projects" "$projects projects"

    # Active service account keys
    local sa_list
    sa_list=$(gcloud iam service-accounts list --format='value(email)' 2>/dev/null)
    local sa_count
    sa_count=$(echo "$sa_list" | grep -c '.' || echo "0")
    log_finding "INFO" "Service Accounts" "$sa_count in project"
}

enum_permissions() {
    log_info "Enumerating GCP IAM bindings..."

    local project
    project=$(gcloud config get-value project 2>/dev/null)

    # Project-level IAM policy
    local policy
    policy=$(gcloud projects get-iam-policy "$project" --format=json 2>/dev/null)

    local account
    account=$(gcloud config get-value account 2>/dev/null)

    # Find current user's roles
    echo "$policy" | jq -r ".bindings[] | select(.members[] | contains(\"$account\")) | .role" 2>/dev/null | while read -r role; do
        case "$role" in
            "roles/owner"|"roles/editor")
                log_finding "HIGH" "Privileged Project Role" "$role" ;;
            "roles/iam.securityAdmin"|"roles/iam.serviceAccountAdmin")
                log_finding "HIGH" "IAM Admin Role" "$role" ;;
            *"admin"*|*"Admin"*)
                log_finding "HIGH" "Admin Role" "$role" ;;
            *)
                log_finding "INFO" "IAM Binding" "$role" ;;
        esac
    done

    # Check for allUsers / allAuthenticatedUsers bindings
    if echo "$policy" | jq -e '.bindings[] | select(.members[] | test("allUsers|allAuthenticatedUsers"))' &>/dev/null; then
        log_finding "CRITICAL" "Public IAM Binding" "Project has allUsers or allAuthenticatedUsers bindings"
    fi

    # Service account impersonation check
    local sa_list
    sa_list=$(gcloud iam service-accounts list --format='value(email)' 2>/dev/null)
    for sa in $sa_list; do
        local sa_policy
        sa_policy=$(gcloud iam service-accounts get-iam-policy "$sa" --format=json 2>/dev/null)
        if echo "$sa_policy" | jq -e ".bindings[] | select(.members[] | contains(\"$account\")) | select(.role | test(\"iam.serviceAccountTokenCreator|iam.serviceAccountUser\"))" &>/dev/null; then
            log_finding "HIGH" "SA Impersonation" "Can impersonate service account: $sa"
        fi
    done
}

enum_services() {
    log_info "Discovering GCP services..."

    # Compute instances
    local instances
    instances=$(gcloud compute instances list --format='value(name)' 2>/dev/null | wc -l)
    log_finding "INFO" "Compute Instances" "$instances instances"

    # GCS Buckets
    local buckets
    buckets=$(gcloud storage ls 2>/dev/null | wc -l)
    log_finding "INFO" "Storage Buckets" "$buckets buckets"

    # Check bucket ACLs
    gcloud storage ls 2>/dev/null | while read -r bucket; do
        local iam
        iam=$(gcloud storage buckets get-iam-policy "$bucket" --format=json 2>/dev/null)
        if echo "$iam" | jq -e '.bindings[] | select(.members[] | test("allUsers|allAuthenticatedUsers"))' &>/dev/null; then
            log_finding "HIGH" "Public Bucket" "$bucket is publicly accessible"
        fi
    done

    # Cloud Functions
    local functions
    functions=$(gcloud functions list --format='value(name)' 2>/dev/null | wc -l)
    log_finding "INFO" "Cloud Functions" "$functions functions"

    # Cloud Run services
    local run_svcs
    run_svcs=$(gcloud run services list --format='value(metadata.name)' 2>/dev/null | wc -l)
    log_finding "INFO" "Cloud Run Services" "$run_svcs services"

    # GKE Clusters
    local gke
    gke=$(gcloud container clusters list --format='value(name)' 2>/dev/null | wc -l)
    log_finding "INFO" "GKE Clusters" "$gke clusters"

    # Cloud SQL
    local sql
    sql=$(gcloud sql instances list --format=json 2>/dev/null)
    local sql_count
    sql_count=$(echo "$sql" | jq 'length' 2>/dev/null || echo "0")
    log_finding "INFO" "Cloud SQL" "$sql_count instances"

    if echo "$sql" | jq -e '.[] | select(.settings.ipConfiguration.authorizedNetworks[] | .value == "0.0.0.0/0")' &>/dev/null; then
        log_finding "HIGH" "Public SQL" "Cloud SQL instance allows 0.0.0.0/0"
    fi

    # BigQuery datasets
    local bq_datasets
    bq_datasets=$(bq ls --format=json 2>/dev/null | jq 'length' 2>/dev/null || echo "0")
    log_finding "INFO" "BigQuery Datasets" "$bq_datasets datasets"

    # Pub/Sub topics
    local topics
    topics=$(gcloud pubsub topics list --format='value(name)' 2>/dev/null | wc -l)
    log_finding "INFO" "Pub/Sub Topics" "$topics topics"
}

enum_network() {
    log_info "Analyzing GCP network configuration..."

    # VPC networks
    local vpcs
    vpcs=$(gcloud compute networks list --format='value(name)' 2>/dev/null | wc -l)
    log_finding "INFO" "VPC Networks" "$vpcs networks"

    # Firewall rules allowing 0.0.0.0/0
    local open_fw
    open_fw=$(gcloud compute firewall-rules list --filter="sourceRanges=0.0.0.0/0 AND direction=INGRESS" \
        --format='value(name,allowed)' 2>/dev/null)
    if [[ -n "$open_fw" ]]; then
        local fw_count
        fw_count=$(echo "$open_fw" | wc -l)
        log_finding "HIGH" "Open Firewall Rules" "$fw_count rules allow ingress from 0.0.0.0/0"
    fi

    # External IPs
    local ext_ips
    ext_ips=$(gcloud compute addresses list --filter="status=IN_USE AND addressType=EXTERNAL" \
        --format='value(address)' 2>/dev/null | wc -l)
    log_finding "INFO" "External IPs" "$ext_ips in use"

    # Cloud NAT
    local nat_count
    nat_count=$(gcloud compute routers nats list --router='' --format='value(name)' 2>/dev/null | wc -l)
    log_finding "INFO" "Cloud NAT" "$nat_count gateways"
}

enum_secrets() {
    log_info "Scanning for exposed secrets..."

    # Secret Manager
    local secrets
    secrets=$(gcloud secrets list --format='value(name)' 2>/dev/null)
    local secret_count
    secret_count=$(echo "$secrets" | grep -c '.' || echo "0")
    [[ $secret_count -gt 0 ]] && log_finding "INFO" "Secret Manager" "$secret_count secrets"

    for secret in $secrets; do
        if gcloud secrets versions access latest --secret="$secret" &>/dev/null; then
            log_finding "HIGH" "Readable Secret" "Can read latest version of '$secret'"
        fi
    done

    # Service account keys
    local sa_list
    sa_list=$(gcloud iam service-accounts list --format='value(email)' 2>/dev/null)
    for sa in $sa_list; do
        local keys
        keys=$(gcloud iam service-accounts keys list --iam-account="$sa" \
            --managed-by=user --format='value(name)' 2>/dev/null | wc -l)
        [[ $keys -gt 0 ]] && log_finding "MEDIUM" "SA User Keys" "$sa has $keys user-managed keys"
    done

    # Cloud Function env vars
    gcloud functions list --format='value(name)' 2>/dev/null | while read -r fn; do
        local env
        env=$(gcloud functions describe "$fn" --format='value(environmentVariables)' 2>/dev/null)
        if echo "$env" | grep -qiE '(password|secret|key|token|api_key)' 2>/dev/null; then
            log_finding "HIGH" "Function Secret in Env" "Function '$fn' has sensitive env vars"
        fi
    done
}

#!/usr/bin/env bash
# S7aba - GCP Data Exfiltration Module

discover_data_stores() {
    log_info "Discovering GCP data stores..."

    # GCS buckets
    gcloud storage ls 2>/dev/null | while read -r bucket; do
        log_finding "INFO" "GCS Bucket" "$bucket"
        local iam
        iam=$(gcloud storage buckets get-iam-policy "$bucket" --format=json 2>/dev/null)
        if echo "$iam" | jq -e '.bindings[] | select(.members[] | test("allUsers"))' &>/dev/null; then
            log_finding "HIGH" "Public GCS Bucket" "$bucket is publicly readable"
        fi
    done

    # BigQuery datasets
    bq ls --format=json 2>/dev/null | jq -r '.[].datasetReference.datasetId' 2>/dev/null | while read -r ds; do
        log_finding "INFO" "BigQuery Dataset" "$ds"
    done

    # Cloud SQL
    gcloud sql instances list --format='value(name,databaseVersion,settings.dataDiskSizeGb)' 2>/dev/null | while read -r name ver size; do
        log_finding "INFO" "Cloud SQL" "$name ($ver, ${size}GB)"
    done

    # Firestore / Datastore
    local firestore
    firestore=$(gcloud firestore databases list --format='value(name)' 2>/dev/null)
    [[ -n "$firestore" ]] && log_finding "INFO" "Firestore" "Database found"

    # Spanner
    local spanner
    spanner=$(gcloud spanner instances list --format='value(name)' 2>/dev/null)
    [[ -n "$spanner" ]] && log_finding "INFO" "Spanner" "Instance found"

    # Secret Manager
    local secrets
    secrets=$(gcloud secrets list --format='value(name)' 2>/dev/null | wc -l)
    [[ $secrets -gt 0 ]] && log_finding "MEDIUM" "Secret Manager" "$secrets secrets"
}

classify_data() {
    log_info "Classifying GCP data sensitivity..."
    # Sample GCS for sensitive patterns
    gcloud storage ls 2>/dev/null | head -5 | while read -r bucket; do
        local objects
        objects=$(gcloud storage ls "$bucket" --recursive 2>/dev/null | head -50)
        if echo "$objects" | grep -qiE '\.(sql|bak|csv|key|pem|env)$'; then
            log_finding "HIGH" "Sensitive Files" "$bucket contains sensitive file types"
        fi
    done
}

evaluate_exfil_channels() {
    log_info "Evaluating GCP exfiltration channels..."
    log_finding "INFO" "gsutil cp" "Copy objects to external GCS bucket"
    log_finding "INFO" "BQ Export" "Export BigQuery tables to GCS then download"
    log_finding "INFO" "SQL Export" "Export Cloud SQL to GCS bucket"
    log_finding "INFO" "Cloud Function" "HTTP function to relay data externally"
    log_finding "INFO" "Compute Exfil" "VM with external IP for data staging"
    log_finding "INFO" "DNS Tunneling" "Encode data in DNS queries"
}

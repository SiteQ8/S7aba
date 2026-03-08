#!/usr/bin/env bash
# S7aba - Cloud Provider Auto-Detection

detect_cloud_provider() {
    # Check metadata endpoints for each provider
    # AWS
    if curl -s --max-time 2 http://169.254.169.254/latest/meta-data/ &>/dev/null; then
        echo "aws"
        return
    fi

    # GCP
    if curl -s --max-time 2 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/ &>/dev/null; then
        echo "gcp"
        return
    fi

    # Azure
    if curl -s --max-time 2 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" &>/dev/null; then
        echo "azure"
        return
    fi

    # Kubernetes
    if [[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]]; then
        echo "k8s"
        return
    fi

    # CLI-based detection
    if cmd_exists aws && aws sts get-caller-identity &>/dev/null 2>&1; then
        echo "aws"
    elif cmd_exists gcloud && gcloud auth list --filter="status:ACTIVE" &>/dev/null 2>&1; then
        echo "gcp"
    elif cmd_exists az && az account show &>/dev/null 2>&1; then
        echo "azure"
    elif cmd_exists kubectl && kubectl cluster-info &>/dev/null 2>&1; then
        echo "k8s"
    else
        echo "unknown"
    fi
}

get_cloud_metadata() {
    local provider="$1"
    case "$provider" in
        aws)
            CURRENT_USER=$(aws sts get-caller-identity --query 'Arn' --output text 2>/dev/null || echo "unknown")
            REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")
            ;;
        gcp)
            CURRENT_USER=$(gcloud config get-value account 2>/dev/null || echo "unknown")
            REGION=$(gcloud config get-value compute/region 2>/dev/null || echo "unknown")
            ;;
        azure)
            CURRENT_USER=$(az account show --query user.name -o tsv 2>/dev/null || echo "unknown")
            REGION=$(az account show --query tenantId -o tsv 2>/dev/null || echo "unknown")
            ;;
        k8s)
            CURRENT_USER=$(kubectl config current-context 2>/dev/null || echo "unknown")
            REGION="cluster"
            ;;
    esac
}

#!/usr/bin/env bash
# S7aba - Kubernetes Data Exfiltration Module

discover_data_stores() {
    log_info "Discovering Kubernetes data stores..."

    # Secrets
    local secret_count
    secret_count=$(kubectl get secrets --all-namespaces --no-headers 2>/dev/null | wc -l)
    log_finding "INFO" "Secrets" "$secret_count secrets across cluster"

    # ConfigMaps with data
    kubectl get configmaps --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | select(.data != null) | "\(.metadata.namespace)/\(.metadata.name) (\(.data | keys | length) keys)"' 2>/dev/null | while read -r cm; do
        log_finding "INFO" "ConfigMap" "$cm"
    done

    # PersistentVolumes
    local pv_count
    pv_count=$(kubectl get pv --no-headers 2>/dev/null | wc -l)
    log_finding "INFO" "Persistent Volumes" "$pv_count PVs"

    # PVCs
    kubectl get pvc --all-namespaces --no-headers 2>/dev/null | while read -r line; do
        local ns pvc
        ns=$(echo "$line" | awk '{print $1}')
        pvc=$(echo "$line" | awk '{print $2}')
        log_finding "INFO" "PVC" "$ns/$pvc"
    done

    # Database pods (common images)
    kubectl get pods --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | select(.spec.containers[].image | test("postgres|mysql|mongo|redis|elasticsearch|cassandra")) | "\(.metadata.namespace)/\(.metadata.name) [\(.spec.containers[0].image)]"' 2>/dev/null | while read -r pod; do
        log_finding "HIGH" "Database Pod" "$pod"
    done
}

classify_data() {
    log_info "Classifying Kubernetes data..."
    # Check secrets for sensitive content
    kubectl get secrets --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | select(.type != "kubernetes.io/service-account-token") | "\(.metadata.namespace)/\(.metadata.name) [\(.type)]"' 2>/dev/null | while read -r s; do
        log_finding "MEDIUM" "Non-Token Secret" "$s"
    done
}

evaluate_exfil_channels() {
    log_info "Evaluating K8s exfiltration channels..."
    log_finding "INFO" "kubectl cp" "Copy files from pod to local system"
    log_finding "INFO" "Pod Exec" "Exec into pod and exfil via curl/wget"
    log_finding "INFO" "Service Exposure" "Create NodePort/LoadBalancer for data access"
    log_finding "INFO" "DNS Exfil" "Encode data in DNS queries from pods"
    log_finding "INFO" "Log Exfil" "Write data to stdout, collect via logging pipeline"
    log_finding "INFO" "Cloud Storage" "If cloud-hosted, use cloud CLI from pod"
}

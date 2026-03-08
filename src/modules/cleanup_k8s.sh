#!/usr/bin/env bash
# S7aba - Kubernetes Cleanup Module

identify_artifacts() {
    log_info "Identifying S7aba artifacts in Kubernetes..."

    # Pods with s7aba label
    local pods
    pods=$(kubectl get pods --all-namespaces -l app=s7aba --no-headers 2>/dev/null)
    [[ -n "$pods" ]] && log_finding "INFO" "S7aba Pods" "$(echo "$pods" | wc -l) pods"

    # S7aba named resources
    for res in pods deployments daemonsets cronjobs clusterrolebindings; do
        local found
        found=$(kubectl get "$res" --all-namespaces --no-headers 2>/dev/null | grep -i "s7aba\|node-monitor\|system-health")
        [[ -n "$found" ]] && log_finding "INFO" "Resource ($res)" "$(echo "$found" | wc -l) found"
    done

    # Audit log
    log_info "Review Kubernetes audit log for complete trail"
}

remove_artifacts() {
    log_warn "Removing S7aba artifacts..."

    # Remove labeled resources
    kubectl delete pods -l app=s7aba --all-namespaces 2>/dev/null && log_success "Removed s7aba pods"
    kubectl delete daemonset node-monitor --ignore-not-found 2>/dev/null && log_success "Removed node-monitor daemonset"
    kubectl delete cronjob system-health-check --ignore-not-found 2>/dev/null && log_success "Removed health-check cronjob"
    kubectl delete pod s7aba-priv --ignore-not-found 2>/dev/null && log_success "Removed priv pod"
    kubectl delete pod s7aba-hostpath --ignore-not-found 2>/dev/null && log_success "Removed hostpath pod"
    kubectl delete clusterrolebinding s7aba-admin --ignore-not-found 2>/dev/null && log_success "Removed admin binding"

    log_success "Kubernetes artifacts cleaned"
}

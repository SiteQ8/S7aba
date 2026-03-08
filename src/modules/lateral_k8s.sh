#!/usr/bin/env bash
# S7aba - Kubernetes Lateral Movement Module

map_trust_relationships() {
    log_info "Mapping Kubernetes trust relationships..."

    # Service accounts with elevated roles
    local crbs
    crbs=$(kubectl get clusterrolebindings -o json 2>/dev/null)
    echo "$crbs" | jq -r '.items[] | select(.roleRef.name | test("admin|cluster-admin")) | .subjects[]? | "\(.namespace // "cluster")/\(.name) (\(.kind))"' 2>/dev/null | while read -r sub; do
        log_finding "HIGH" "Privileged Binding" "$sub has admin-level access"
    done

    # Service accounts with automounted tokens
    kubectl get serviceaccounts --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | select(.automountServiceAccountToken != false) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null | while read -r sa; do
        log_finding "INFO" "Automount Token" "$sa"
    done
}

find_pivot_points() {
    log_info "Identifying K8s pivot points..."

    # Pods in kube-system (often have elevated access)
    local ks_pods
    ks_pods=$(kubectl get pods -n kube-system --no-headers 2>/dev/null | wc -l)
    log_finding "INFO" "kube-system Pods" "$ks_pods pods"

    # Pods with hostPath mounts
    kubectl get pods --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | select(.spec.volumes[]? | .hostPath) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null | while read -r pod; do
        log_finding "HIGH" "HostPath Mount" "$pod has hostPath volume"
    done

    # Cloud provider metadata accessible from pods
    if kubectl run s7aba-meta --image=alpine --restart=Never --rm -i --command -- \
        wget -qO- --timeout=2 http://169.254.169.254/ &>/dev/null; then
        log_finding "HIGH" "Metadata Access" "Cloud metadata service reachable from pods"
    fi

    # etcd access
    if kubectl get endpoints -n kube-system etcd &>/dev/null; then
        log_finding "CRITICAL" "etcd Endpoint" "etcd endpoint discoverable"
    fi
}

enumerate_targets() {
    log_info "Enumerating K8s targets..."

    # All namespaces and their workloads
    kubectl get namespaces --no-headers 2>/dev/null | awk '{print $1}' | while read -r ns; do
        local pod_count
        pod_count=$(kubectl get pods -n "$ns" --no-headers 2>/dev/null | wc -l)
        log_finding "INFO" "Namespace" "$ns ($pod_count pods)"
    done

    # Nodes
    kubectl get nodes -o wide --no-headers 2>/dev/null | while read -r line; do
        local name
        name=$(echo "$line" | awk '{print $1}')
        local ip
        ip=$(echo "$line" | awk '{print $6}')
        log_finding "INFO" "Node" "$name ($ip)"
    done
}

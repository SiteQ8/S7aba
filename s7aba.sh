#!/usr/bin/env bash
#
#  ███████╗███████╗██╗  ██╗ █████╗ ██████╗  █████╗
#  ██╔════╝╚════██║██║  ██║██╔══██╗██╔══██╗██╔══██╗
#  ███████╗    ██╔╝███████║███████║██████╔╝███████║
#  ╚════██║   ██╔╝ ╚════██║██╔══██║██╔══██╗██╔══██║
#  ███████║   ██║       ██║██║  ██║██████╔╝██║  ██║
#  ╚══════╝   ╚═╝       ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝
#
#  S7aba - Cloud Privilege Escalation & Post-Exploitation Framework
#  Author: Ali AlEnezi (@SiteQ8)
#  License: MIT
#  Version: 1.0.0
#
#  FOR AUTHORIZED SECURITY TESTING ONLY
#  Usage of this tool for attacking targets without prior mutual consent
#  is illegal. The author assumes no liability.
#

set -euo pipefail

# ─── Constants ───────────────────────────────────────────────────────────────
readonly VERSION="1.0.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly MODULES_DIR="${SCRIPT_DIR}/src/modules"
readonly LIB_DIR="${SCRIPT_DIR}/src/lib"
readonly LOG_DIR="${SCRIPT_DIR}/logs"
readonly REPORT_DIR="${SCRIPT_DIR}/reports"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# ─── Colors ──────────────────────────────────────────────────────────────────
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly DIM='\033[2m'
readonly BOLD='\033[1m'
readonly RESET='\033[0m'

# ─── Global State ────────────────────────────────────────────────────────────
CLOUD_PROVIDER=""
CURRENT_USER=""
CURRENT_ROLE=""
REGION=""
VERBOSE=0
DRY_RUN=0
OUTPUT_FORMAT="text"
REPORT_FILE=""

# ─── Library Loading ─────────────────────────────────────────────────────────
source_lib() {
    local lib_file="${LIB_DIR}/$1"
    if [[ -f "$lib_file" ]]; then
        source "$lib_file"
    else
        echo -e "${RED}[!] Missing library: $1${RESET}" >&2
        exit 1
    fi
}

source_lib "utils.sh"
source_lib "logger.sh"
source_lib "cloud_detect.sh"

# ─── Banner ──────────────────────────────────────────────────────────────────
show_banner() {
    echo -e "${CYAN}"
    cat << 'BANNER'

    ██████╗ ██████╗  █████╗ ██████╗  █████╗
    ██╔════╝╚════██╗██╔══██╗██╔══██╗██╔══██╗
    ███████╗    ██╔╝███████║██████╔╝███████║
    ╚════██║   ██╔╝ ╚════██║██╔══██╗██╔══██║
    ███████║   ██║       ██║██████╔╝██║  ██║
    ╚══════╝   ╚═╝       ╚═╝╚═════╝ ╚═╝  ╚═╝

BANNER
    echo -e "${WHITE}    Cloud Privilege Escalation & Post-Exploitation${RESET}"
    echo -e "${DIM}    v${VERSION} | @SiteQ8 | For authorized testing only${RESET}"
    echo ""
}

# ─── Help Menu ───────────────────────────────────────────────────────────────
show_help() {
    show_banner
    echo -e "${BOLD}USAGE${RESET}"
    echo -e "  ./s7aba.sh [OPTIONS] <COMMAND> [ARGS]"
    echo ""
    echo -e "${BOLD}COMMANDS${RESET}"
    echo -e "  ${GREEN}recon${RESET}          Enumerate cloud environment & permissions"
    echo -e "  ${GREEN}privesc${RESET}        Identify & exploit privilege escalation paths"
    echo -e "  ${GREEN}persist${RESET}        Establish persistence mechanisms"
    echo -e "  ${GREEN}exfil${RESET}          Data discovery & exfiltration techniques"
    echo -e "  ${GREEN}lateral${RESET}        Lateral movement across cloud services"
    echo -e "  ${GREEN}cleanup${RESET}        Remove artifacts & cover tracks"
    echo -e "  ${GREEN}report${RESET}         Generate assessment report"
    echo -e "  ${GREEN}interactive${RESET}    Launch interactive TUI mode"
    echo ""
    echo -e "${BOLD}OPTIONS${RESET}"
    echo -e "  ${YELLOW}-p, --provider${RESET}   Target cloud (aws|azure|gcp|k8s|multi)"
    echo -e "  ${YELLOW}-r, --region${RESET}     Target region"
    echo -e "  ${YELLOW}-o, --output${RESET}     Output format (text|json|html|pdf)"
    echo -e "  ${YELLOW}-v, --verbose${RESET}    Verbose output"
    echo -e "  ${YELLOW}-d, --dry-run${RESET}    Simulate without executing"
    echo -e "  ${YELLOW}-h, --help${RESET}       Show this help"
    echo -e "  ${YELLOW}--version${RESET}        Show version"
    echo ""
    echo -e "${BOLD}EXAMPLES${RESET}"
    echo -e "  ${DIM}# Auto-detect cloud & enumerate permissions${RESET}"
    echo -e "  ./s7aba.sh recon"
    echo ""
    echo -e "  ${DIM}# AWS privilege escalation scan${RESET}"
    echo -e "  ./s7aba.sh -p aws privesc"
    echo ""
    echo -e "  ${DIM}# Kubernetes lateral movement (dry-run)${RESET}"
    echo -e "  ./s7aba.sh -p k8s -d lateral"
    echo ""
    echo -e "  ${DIM}# Generate HTML report${RESET}"
    echo -e "  ./s7aba.sh -o html report"
    echo ""
}

# ─── Version ─────────────────────────────────────────────────────────────────
show_version() {
    echo -e "S7aba v${VERSION}"
}

# ─── Prerequisite Check ─────────────────────────────────────────────────────
check_prerequisites() {
    local missing=()
    local tools=("curl" "jq" "grep" "awk" "sed" "base64")

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing[*]}"
        echo -e "${YELLOW}[*] Install with: sudo apt-get install ${missing[*]}${RESET}"
        exit 1
    fi

    # Check cloud CLI tools
    local cloud_tools=()
    command -v aws &>/dev/null && cloud_tools+=("aws")
    command -v az &>/dev/null && cloud_tools+=("azure")
    command -v gcloud &>/dev/null && cloud_tools+=("gcp")
    command -v kubectl &>/dev/null && cloud_tools+=("k8s")

    if [[ ${#cloud_tools[@]} -eq 0 ]]; then
        log_warn "No cloud CLI tools detected. Install at least one: aws-cli, azure-cli, gcloud, kubectl"
    else
        log_info "Detected cloud tools: ${cloud_tools[*]}"
    fi
}

# ─── Init ────────────────────────────────────────────────────────────────────
init() {
    mkdir -p "$LOG_DIR" "$REPORT_DIR"
    REPORT_FILE="${REPORT_DIR}/s7aba_report_${TIMESTAMP}.${OUTPUT_FORMAT}"
    log_init "${LOG_DIR}/s7aba_${TIMESTAMP}.log"

    check_prerequisites

    if [[ -z "$CLOUD_PROVIDER" ]]; then
        log_info "Auto-detecting cloud environment..."
        CLOUD_PROVIDER=$(detect_cloud_provider)
        log_success "Detected provider: ${CLOUD_PROVIDER}"
    fi
}

# ─── Command Dispatch ────────────────────────────────────────────────────────

cmd_recon() {
    log_section "RECONNAISSANCE"
    local module="${MODULES_DIR}/recon_${CLOUD_PROVIDER}.sh"

    if [[ ! -f "$module" ]]; then
        log_error "Recon module not found for provider: ${CLOUD_PROVIDER}"
        exit 1
    fi

    source "$module"

    log_step "Enumerating identity & credentials"
    enum_identity

    log_step "Mapping IAM permissions"
    enum_permissions

    log_step "Discovering services & resources"
    enum_services

    log_step "Checking network configuration"
    enum_network

    log_step "Scanning for secrets & sensitive data"
    enum_secrets

    log_success "Recon complete. Results saved to ${LOG_DIR}/"
}

cmd_privesc() {
    log_section "PRIVILEGE ESCALATION"
    local module="${MODULES_DIR}/privesc_${CLOUD_PROVIDER}.sh"

    if [[ ! -f "$module" ]]; then
        log_error "Privesc module not found for provider: ${CLOUD_PROVIDER}"
        exit 1
    fi

    source "$module"

    log_step "Analyzing current permissions"
    analyze_permissions

    log_step "Identifying escalation paths"
    local paths
    paths=$(find_escalation_paths)

    if [[ -z "$paths" ]]; then
        log_warn "No privilege escalation paths found"
        return
    fi

    echo -e "\n${BOLD}Discovered Escalation Paths:${RESET}\n"
    echo "$paths" | while IFS='|' read -r risk method description; do
        local color=$GREEN
        [[ "$risk" == "HIGH" ]] && color=$RED
        [[ "$risk" == "MEDIUM" ]] && color=$YELLOW
        echo -e "  ${color}[${risk}]${RESET} ${BOLD}${method}${RESET}"
        echo -e "         ${DIM}${description}${RESET}"
    done

    if [[ $DRY_RUN -eq 0 ]]; then
        echo ""
        read -rp "$(echo -e "${YELLOW}[?] Attempt exploitation? [y/N]: ${RESET}")" confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            exploit_paths "$paths"
        fi
    else
        log_info "Dry-run mode: skipping exploitation"
    fi
}

cmd_persist() {
    log_section "PERSISTENCE"
    local module="${MODULES_DIR}/persist_${CLOUD_PROVIDER}.sh"
    [[ ! -f "$module" ]] && { log_error "Module not found: persist_${CLOUD_PROVIDER}"; exit 1; }
    source "$module"

    log_step "Evaluating persistence techniques"
    enumerate_persistence_options

    log_step "Deploying persistence mechanism"
    if [[ $DRY_RUN -eq 1 ]]; then
        log_info "Dry-run: would deploy persistence"
    else
        deploy_persistence
    fi
}

cmd_exfil() {
    log_section "DATA EXFILTRATION"
    local module="${MODULES_DIR}/exfil_${CLOUD_PROVIDER}.sh"
    [[ ! -f "$module" ]] && { log_error "Module not found: exfil_${CLOUD_PROVIDER}"; exit 1; }
    source "$module"

    log_step "Discovering sensitive data stores"
    discover_data_stores

    log_step "Classifying data sensitivity"
    classify_data

    log_step "Evaluating exfiltration channels"
    evaluate_exfil_channels
}

cmd_lateral() {
    log_section "LATERAL MOVEMENT"
    local module="${MODULES_DIR}/lateral_${CLOUD_PROVIDER}.sh"
    [[ ! -f "$module" ]] && { log_error "Module not found: lateral_${CLOUD_PROVIDER}"; exit 1; }
    source "$module"

    log_step "Mapping trust relationships"
    map_trust_relationships

    log_step "Identifying cross-service pivots"
    find_pivot_points

    log_step "Enumerating reachable targets"
    enumerate_targets
}

cmd_cleanup() {
    log_section "CLEANUP"
    local module="${MODULES_DIR}/cleanup_${CLOUD_PROVIDER}.sh"
    [[ ! -f "$module" ]] && { log_error "Module not found: cleanup_${CLOUD_PROVIDER}"; exit 1; }
    source "$module"

    log_step "Identifying artifacts"
    identify_artifacts

    log_step "Removing traces"
    if [[ $DRY_RUN -eq 1 ]]; then
        log_info "Dry-run: would remove artifacts"
    else
        remove_artifacts
    fi

    log_success "Cleanup complete"
}

cmd_report() {
    log_section "REPORT GENERATION"
    log_step "Aggregating findings"

    local report_module="${MODULES_DIR}/report.sh"
    [[ ! -f "$report_module" ]] && { log_error "Report module not found"; exit 1; }
    source "$report_module"

    generate_report "$OUTPUT_FORMAT" "$REPORT_FILE"
    log_success "Report saved to: ${REPORT_FILE}"
}

cmd_interactive() {
    log_section "INTERACTIVE MODE"
    show_banner

    while true; do
        echo -e "\n${CYAN}┌──(${WHITE}s7aba${CYAN})─[${GREEN}${CLOUD_PROVIDER:-unknown}${CYAN}]"
        echo -ne "${CYAN}└─${WHITE}\$ ${RESET}"
        read -r input

        case "$input" in
            recon)      cmd_recon ;;
            privesc)    cmd_privesc ;;
            persist)    cmd_persist ;;
            exfil)      cmd_exfil ;;
            lateral)    cmd_lateral ;;
            cleanup)    cmd_cleanup ;;
            report)     cmd_report ;;
            help|?)     show_help ;;
            exit|quit)  echo -e "${GREEN}[+] Exiting S7aba. Stay ethical.${RESET}"; exit 0 ;;
            "")         continue ;;
            *)          echo -e "${RED}[!] Unknown command: ${input}. Type 'help' for usage.${RESET}" ;;
        esac
    done
}

# ─── Argument Parsing ────────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p|--provider)
                CLOUD_PROVIDER="$2"
                shift 2
                ;;
            -r|--region)
                REGION="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=1
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            --version)
                show_version
                exit 0
                ;;
            recon|privesc|persist|exfil|lateral|cleanup|report|interactive)
                COMMAND="$1"
                shift
                ;;
            *)
                echo -e "${RED}[!] Unknown option: $1${RESET}"
                show_help
                exit 1
                ;;
        esac
    done
}

# ─── Main ────────────────────────────────────────────────────────────────────
main() {
    local COMMAND=""

    parse_args "$@"

    if [[ -z "$COMMAND" ]]; then
        show_help
        exit 0
    fi

    show_banner
    init

    case "$COMMAND" in
        recon)       cmd_recon ;;
        privesc)     cmd_privesc ;;
        persist)     cmd_persist ;;
        exfil)       cmd_exfil ;;
        lateral)     cmd_lateral ;;
        cleanup)     cmd_cleanup ;;
        report)      cmd_report ;;
        interactive) cmd_interactive ;;
    esac
}

main "$@"

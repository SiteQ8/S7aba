#!/usr/bin/env bash
# S7aba - Logging Functions

LOG_FILE=""

log_init() {
    LOG_FILE="$1"
    echo "# S7aba Log - $(now)" > "$LOG_FILE"
}

_log() {
    local level="$1" color="$2" msg="$3"
    echo -e "${color}[${level}]${RESET} ${msg}"
    [[ -n "$LOG_FILE" ]] && echo "[$(now)] [${level}] ${msg}" >> "$LOG_FILE"
}

log_info()    { _log "*" "$BLUE" "$1"; }
log_success() { _log "+" "$GREEN" "$1"; }
log_warn()    { _log "!" "$YELLOW" "$1"; }
log_error()   { _log "✗" "$RED" "$1"; }
log_debug()   { [[ $VERBOSE -eq 1 ]] && _log "DBG" "$DIM" "$1"; }

log_section() {
    local title="$1"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${WHITE}  $title${RESET}"
    echo -e "${CYAN}═══════════════════════════════════════════════════${RESET}"
    echo ""
    [[ -n "$LOG_FILE" ]] && echo -e "\n=== $title ===" >> "$LOG_FILE"
}

log_step() {
    echo -e "  ${MAGENTA}▸${RESET} ${WHITE}$1${RESET}"
    [[ -n "$LOG_FILE" ]] && echo "[$(now)] [STEP] $1" >> "$LOG_FILE"
}

log_finding() {
    local severity="$1" title="$2" detail="$3"
    local color=$GREEN
    [[ "$severity" == "HIGH" ]] && color=$RED
    [[ "$severity" == "MEDIUM" ]] && color=$YELLOW
    [[ "$severity" == "CRITICAL" ]] && color=$RED

    echo -e "    ${color}● [${severity}]${RESET} ${BOLD}${title}${RESET}"
    [[ -n "$detail" ]] && echo -e "      ${DIM}${detail}${RESET}"
    [[ -n "$LOG_FILE" ]] && echo "[$(now)] [FINDING:${severity}] ${title} - ${detail}" >> "$LOG_FILE"
}

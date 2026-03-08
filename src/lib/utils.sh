#!/usr/bin/env bash
# S7aba - Utility Functions

# Check if running as root
is_root() { [[ $EUID -eq 0 ]]; }

# Check if command exists
cmd_exists() { command -v "$1" &>/dev/null; }

# URL encode string
urlencode() {
    local string="$1"
    python3 -c "import urllib.parse; print(urllib.parse.quote('$string'))" 2>/dev/null || echo "$string"
}

# Base64 encode/decode
b64encode() { echo -n "$1" | base64 2>/dev/null; }
b64decode() { echo -n "$1" | base64 -d 2>/dev/null; }

# JSON helpers
json_get() { echo "$1" | jq -r "$2" 2>/dev/null; }

# Safe temp file
safe_tmp() { mktemp /tmp/s7aba.XXXXXX; }

# Spinner animation
spinner() {
    local pid=$1 msg="${2:-Working...}"
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${CYAN}  %s ${WHITE}%s${RESET}" "${spin:i++%${#spin}:1}" "$msg"
        sleep 0.1
    done
    printf "\r\033[K"
}

# Progress bar
progress_bar() {
    local current=$1 total=$2 width=40
    local pct=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    printf "\r  ${CYAN}[${GREEN}%*s${DIM}%*s${CYAN}]${RESET} %3d%%" 0 "$(printf '█%.0s' $(seq 1 $filled))" 0 "$(printf '░%.0s' $(seq 1 $empty))" "$pct"
}

# HTTP request wrapper
http_get() {
    local url="$1"
    curl -sS --max-time 10 -H "User-Agent: S7aba/${VERSION}" "$url" 2>/dev/null
}

# Validate IP address
valid_ip() {
    local ip=$1
    [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
}

# Validate CIDR
valid_cidr() {
    local cidr=$1
    [[ $cidr =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]
}

# Timestamp
now() { date '+%Y-%m-%d %H:%M:%S'; }

# File size human readable
human_size() {
    local bytes=$1
    if ((bytes >= 1073741824)); then echo "$((bytes / 1073741824))GB"
    elif ((bytes >= 1048576)); then echo "$((bytes / 1048576))MB"
    elif ((bytes >= 1024)); then echo "$((bytes / 1024))KB"
    else echo "${bytes}B"
    fi
}

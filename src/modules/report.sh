#!/usr/bin/env bash
# S7aba - Report Generation Module

generate_report() {
    local format="$1" output="$2"
    
    case "$format" in
        json)
            generate_json_report "$output"
            ;;
        html)
            generate_html_report "$output"
            ;;
        *)
            generate_text_report "$output"
            ;;
    esac
}

generate_text_report() {
    local output="$1"
    {
        echo "═══════════════════════════════════════════"
        echo "  S7aba Assessment Report"
        echo "  Generated: $(now)"
        echo "  Provider: ${CLOUD_PROVIDER}"
        echo "═══════════════════════════════════════════"
        echo ""
        cat "${LOG_DIR}"/s7aba_*.log 2>/dev/null | grep "\[FINDING" | sort -t: -k2
    } > "$output"
}

generate_json_report() {
    local output="$1"
    local findings=()
    while IFS= read -r line; do
        findings+=("$line")
    done < <(cat "${LOG_DIR}"/s7aba_*.log 2>/dev/null | grep "\[FINDING")
    
    jq -n --argjson count "${#findings[@]}" \
        --arg provider "$CLOUD_PROVIDER" \
        --arg timestamp "$(now)" \
        '{tool:"S7aba",version:"'"$VERSION"'",provider:$provider,timestamp:$timestamp,finding_count:$count}' > "$output"
}

generate_html_report() {
    local output="$1"
    cat > "$output" << HTML
<!DOCTYPE html>
<html><head><title>S7aba Report</title></head>
<body style="font-family:monospace;background:#0a0a0a;color:#00ff88;padding:2rem;">
<h1>S7aba Assessment Report</h1>
<p>Provider: ${CLOUD_PROVIDER} | Generated: $(now)</p>
<pre>$(cat "${LOG_DIR}"/s7aba_*.log 2>/dev/null | grep "\[FINDING" | sort -t: -k2)</pre>
</body></html>
HTML
}

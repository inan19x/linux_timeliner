#!/bin/bash

export LC_TIME=C
# export TZ=UTC

SECURE_LOG="/var/log/secure"
CRON_LOG="/var/log/cron"
MESSAGES_LOG="/var/log/messages"
AUDIT_LOG="/var/log/audit/audit.log"
SURICATA_LOG="/usr/local//var/log/suricata/fast.log"
HTTP_LOG="/var/log/httpd/access_log"
SQUID_LOG="/var/log/squid/access.log"
WAZUH_LOG="/var/ossec/logs/ossec.log"

HOSTNAME=$(hostname)
OUTPUT_FILE="timeline_${HOSTNAME}.csv"
TMP_FILE=$(mktemp)

CURRENT_YEAR=$(date +%Y)

START="$1"
END="$2"

if [[ -z "$START" || -z "$END" ]]; then
    echo "Usage: $0 \"START\" \"END\""
    exit 1
fi

echo "========================================================================"
echo "[STARTING...] linux_timeliner.sh - RHEL/CentOS logs timeline builder"
echo "========================================================================"
echo "[INFO] Building timeline from $START to $END"

# =========================
# SYSLOG PARSER
# =========================
parse_syslog_file() {
    local file="$1"
    local source="$2"

    [[ -f "$file" ]] || { echo "[SKIP] $source"; return; }

    echo "[INFO] Parsing $source"

    awk -v year="$CURRENT_YEAR" -v start="$START" -v end="$END" -v src="$source" '
    function mon2num(mon) {
        split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " ")
        for (i=1;i<=12;i++) if (m[i]==mon) return i
    }
    function pad(n){ return (n<10?"0":"") n }

    {
        ts=year "/" pad(mon2num($1)) "/" pad($2) " " $3

        if (ts >= start && ts <= end) {
            $1=$2=$3=""
            sub(/^ +/, "")
            line=$0

            flag=""
            if (tolower(line) ~ /failed/) flag="FAILED_LOGIN"
            else if (tolower(line) ~ /sudo/) flag="SUDO_LOGIN"

            gsub(/"/, "\"\"", line)
            print "\"" ts "\",\"" line "\",\"" src "\",\"" flag "\""
        }
    }' "$file" >> "$TMP_FILE"
}

# =========================
# HTTP
# =========================
parse_http_log() {
    [[ -f "$HTTP_LOG" ]] || { echo "[SKIP] HTTP_LOG"; return; }

    echo "[INFO] Parsing HTTP_LOG"

    awk -v start="$START" -v end="$END" '
    function mon2num(mon) {
        split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " ")
        for (i=1;i<=12;i++) if (m[i]==mon) return i
    }
    function pad(n){ return (n<10?"0":"") n }

    {
        # Match timestamp inside brackets
        match($0, /\[([0-9]+)\/([A-Za-z]+)\/([0-9]+):([0-9:]+)/, a)
        if (a[0] != "") {
            ts=a[3] "/" pad(mon2num(a[2])) "/" pad(a[1]) " " a[4]

            if (ts >= start && ts <= end) {
                # Extract full request inside quotes (GET/POST URL HTTP)
                request=""
                if (match($0, /"[^"]+"/)) {
                    request=substr($0, RSTART, RLENGTH)
                }

                event=$1" "request" "$9   # IP + full request + status

                flag=""
                if ($9 ~ /^[45]/) flag="HTTP_ERROR"
                if (tolower($0) ~ /admin|login|sql/) {
                    if (flag!="") flag=flag";WEB_ALERT"
                    else flag="WEB_ALERT"
                }

                gsub(/"/, "\"\"", event)
                print "\"" ts "\",\"" event "\",\"HTTP_LOG\",\"" flag "\""
            }
        }
    }' "$HTTP_LOG" >> "$TMP_FILE"
}

# =========================
# SQUID
# =========================
parse_squid_log() {
    [[ -f "$SQUID_LOG" ]] || { echo "[SKIP] SQUID_LOG"; return; }

    echo "[INFO] Parsing SQUID_LOG"

    awk -v start="$START" -v end="$END" '
    {
        if ($1 ~ /^[0-9]+(\.[0-9]+)?$/) {       # Only process if $1 is a number
            cmd="date -d @"$1" +\"%Y/%m/%d %H:%M:%S\""
            cmd | getline ts
            close(cmd)

            if (ts >= start && ts <= end) {
                flag=""
                if ($4 ~ /^[45]/) flag="HTTP_ERROR"

		line=$0
		# Remove the first field (epoch timestamp)
		$1=""; sub(/^ +/, "")
		line=$0
                gsub(/"/, "\"\"", line)
                print "\"" ts "\",\"" line "\",\"SQUID_LOG\",\"" flag "\""
            }
        }
    }' "$SQUID_LOG" >> "$TMP_FILE"
}

# =========================
# SURICATA
# =========================
parse_suricata_log() {
    [[ -f "$SURICATA_LOG" ]] || { echo "[SKIP] SURICATA_LOG"; return; }

    echo "[INFO] Parsing SURICATA_LOG"

    awk -v start="$START" -v end="$END" '
    function pad(n){ return (n<10?"0":"") n }
    {
        # Skip empty or malformed lines
        if ($1 == "") next

        # Extract timestamp: 03/12/2026-20:09:54.497216
        if (match($1, /^([0-9]{2})\/([0-9]{2})\/([0-9]{4})-([0-9]{2}:[0-9]{2}:[0-9]{2})/, a)) {
            ts = a[3] "/" a[1] "/" a[2] " " a[4]   # YYYY/MM/DD HH:MM:SS

            if (ts >= start && ts <= end) {
                flag="SURICATA_ALERT"  # Always flagged

		line=$0
		# Remove leading "MM/DD/YYYY-HH:MM:SS.mmmmmm "
		sub(/^[0-9]{2}\/[0-9]{2}\/[0-9]{4}-[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+[ \t]+/, "", $0)
		line=$0
		gsub(/"/, "\"\"", line)
                print "\"" ts "\",\"" line "\",\"SURICATA_LOG\",\"" flag "\""
            }
        }
    }' "$SURICATA_LOG" >> "$TMP_FILE"
}

# =========================
# WAZUH
# =========================
parse_wazuh_log() {
    [[ -f "$WAZUH_LOG" ]] || { echo "[SKIP] WAZUH_LOG"; return; }

    echo "[INFO] Parsing WAZUH_LOG"

    awk -v start="$START" -v end="$END" '
    {
        ts=$1" "$2

        if (ts >= start && ts <= end) {
            flag=""
            if (tolower($0) ~ /error|alert|failed/) flag="WAZUH_ALERT"

	    line=$0
	    # Remove first word (timestamp) from event
	    sub(/^[0-9]{4}\/[0-9]{2}\/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}[ \t]+/, "", $0)
	    line=$0
	    gsub(/"/, "\"\"", line)
            print "\"" ts "\",\"" line "\",\"WAZUH_LOG\",\"" flag "\""
        }
    }' "$WAZUH_LOG" >> "$TMP_FILE"
}

# =========================
# LAST / LASTB
# =========================
parse_last_logs() {
    echo "[INFO] Parsing LAST"

    last -F 2>/dev/null | while read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^reboot|^shutdown ]] && continue

        # Extract weekday month day HH:MM:SS year
        if [[ "$line" =~ ([A-Z][a-z]{2})[[:space:]]+([A-Z][a-z]{2})[[:space:]]+([0-9]{1,2})[[:space:]]+([0-9]{2}:[0-9]{2}:[0-9]{2})[[:space:]]+([0-9]{4}) ]]; then
            weekday="${BASH_REMATCH[1]}"
            month="${BASH_REMATCH[2]}"
            day="${BASH_REMATCH[3]}"
            time="${BASH_REMATCH[4]}"
            year="${BASH_REMATCH[5]}"

            ts="$day $month $year $time"
            fmt=$(date -d "$ts" +"%Y/%m/%d %H:%M:%S" 2>/dev/null)
            [[ -z "$fmt" ]] && continue
            [[ "$fmt" < "$START" || "$fmt" > "$END" ]] && continue  # Filter by date range

            flag=""
            [[ "$line" =~ root|sudo ]] && flag="SUDO_LOGIN"
            event=${line//\"/\"\"}
            echo "\"$fmt\",\"$event\",\"LAST\",\"$flag\"" >> "$TMP_FILE"
        fi
    done

    echo "[INFO] Parsing LASTB"

    lastb -F 2>/dev/null | while read -r line; do
        [[ -z "$line" ]] && continue

        if [[ "$line" =~ ([A-Z][a-z]{2})[[:space:]]+([A-Z][a-z]{2})[[:space:]]+([0-9]{1,2})[[:space:]]+([0-9]{2}:[0-9]{2}:[0-9]{2})[[:space:]]+([0-9]{4}) ]]; then
            weekday="${BASH_REMATCH[1]}"
            month="${BASH_REMATCH[2]}"
            day="${BASH_REMATCH[3]}"
            time="${BASH_REMATCH[4]}"
            year="${BASH_REMATCH[5]}"

            ts="$day $month $year $time"
            fmt=$(date -d "$ts" +"%Y/%m/%d %H:%M:%S" 2>/dev/null)
            [[ -z "$fmt" ]] && continue
            [[ "$fmt" < "$START" || "$fmt" > "$END" ]] && continue  # Filter by date range

            event=${line//\"/\"\"}
            echo "\"$fmt\",\"$event\",\"LASTB\",\"FAILED_LOGIN\"" >> "$TMP_FILE"
        fi
    done
}

# =========================
# AUDIT
# =========================
parse_audit_log() {
    [[ -f "$AUDIT_LOG" ]] || { echo "[SKIP] AUDIT_LOG"; return; }

    echo "[INFO] Parsing AUDIT_LOG"

    awk -v start="$START" -v end="$END" '
    match($0, /msg=audit\(([0-9]+)\.[0-9]+:/, a) {
        epoch=a[1]
        cmd="date -d @"epoch" +\"%Y/%m/%d %H:%M:%S\""
        cmd | getline ts
        close(cmd)

        if (ts >= start && ts <= end) {
            flag=""
            if (tolower($0) ~ /user_login|user_auth/) flag="AUDIT_ALERT"

            line=$0
            gsub(/"/, "\"\"", line)
            print "\"" ts "\",\"" line "\",\"AUDIT_LOG\",\"" flag "\""
        }
    }' "$AUDIT_LOG" >> "$TMP_FILE"
}

# =========================
# RUN
# =========================
> "$TMP_FILE"

parse_syslog_file "$SECURE_LOG" "SECURE_LOG"
parse_syslog_file "$CRON_LOG" "CRON_LOG"
parse_syslog_file "$MESSAGES_LOG" "MESSAGES_LOG"
parse_http_log
parse_squid_log
parse_suricata_log
parse_wazuh_log
parse_last_logs
parse_audit_log

echo "[INFO] Sorting output..."

echo "\"Timestamp\",\"Event\",\"Source\",\"Flags\"" > "$OUTPUT_FILE"
sort -t, -k1,1 "$TMP_FILE" >> "$OUTPUT_FILE"

rm -f "$TMP_FILE"

echo "[DONE] Timeline created: $OUTPUT_FILE"

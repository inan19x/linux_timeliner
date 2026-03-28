# linux_timeliner.sh - Linux Timeline Builder

linux_timeliner.sh is a Bash script that collects and parses multiple Linux log sources to generate a unified, chronological CSV timeline. It supports logs from:
- /var/log/secure, /var/log/cron, /var/log/messages
- Apache HTTPD (/var/log/httpd/access_log)
- Squid (/var/log/squid/access.log)
- Wazuh (/var/ossec/logs/ossec.log)
- Suricata (/usr/local/var/log/suricata/fast.log)
- last/lastb login history
- Audit logs (/var/log/audit/audit.log)

The script flags important events like failed logins, sudo usage, web alerts, IDS alerts, and audit events, producing a CSV file that is ready for forensic analysis.

## Usage:
```./linux_timeliner.sh "YYYY/MM/DD HH:MM:SS" "YYYY/MM/DD HH:MM:SS"```

## Usage Example:
```./linux_timeliner.sh "2025/12/31 20:00:00" "2025/12/31 21:00:00"```

## Output: 
```timeline_<hostname>.csv```

## Output Example:
```timeline_darkstar.csv```

| Timestamp           | Event                                                                                                                | Source       | Flags          |
| ------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------ | -------------- |
| 2025/12/31 20:08:19 | (dev1) CMD (/tmp/x88aGH9z.sh)                                                                                        | CRON_LOG     |                |
| 2025/12/31 20:09:29 | kernel: [ 1413.547803] device enp0s3 entered promiscuous mode                                                        | MESSAGES_LOG |                |
| 2025/12/31 20:10:42 | 162.216.149.105 "POST /webapp/admin/file_upload.php HTTP/1.1"                                                        | HTTP_LOG     | WEB_ALERT      |
| 2025/12/31 20:12:24 | [\*\*] [1:1000012:1] Possible staged C2 reverse shell detected ...                                                   | SURICATA_LOG | SURICATA_ALERT |
| 2025/12/31 20:56:35 | 730 172.16.1.10 TCP_MISS/200 2829528 GET [h++ps://hacking.evil.lab/](h++ps://hacking.evil.lab/)...                   | SQUID_LOG    |                |

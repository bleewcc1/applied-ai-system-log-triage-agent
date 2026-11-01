"""
specialized_fewshot_dataset.py

A small synthetic dataset of labeled log examples used as the few-shot
corpus for specialized_agent.py. Each entry is a short, representative
log snippet paired with its correct log_type and severity - these are
NOT the project's real sample logs in logs/ (those stay untouched as the
evaluation fixtures); this is a separate, deliberately more varied set
written to give the Chroma retriever something genuinely useful to match
against across severities and both log families.
"""

FEW_SHOT_EXAMPLES = [
    # --- network_intrusion: critical ---
    {
        "id": "fs-01",
        "text": "[**] [1:2019401:3] ET EXPLOIT Possible Log4j RCE Attempt [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] 203.0.113.44:443 -> 10.0.0.9:8080 TCP",
        "log_type": "network_intrusion",
        "severity": "critical",
    },
    {
        "id": "fs-02",
        "text": "[**] [1:2024897:2] ET MALWARE Cobalt Strike Beacon Observed [**] [Classification: A Network Trojan was Detected] [Priority: 1] 198.51.100.7:4444 -> 10.0.0.22:51331 TCP",
        "log_type": "network_intrusion",
        "severity": "critical",
    },
    {
        "id": "fs-03",
        "text": "[**] [1:1000045:1] LOCAL Ransomware C2 beacon detected [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] 203.0.113.91:443 -> 10.0.0.14:49512 TCP",
        "log_type": "network_intrusion",
        "severity": "critical",
    },
    # --- network_intrusion: high ---
    {
        "id": "fs-04",
        "text": "[**] [1:2101200:3] GPL SCAN Nikto Web App Scan detected [**] [Classification: Web Application Attack] [Priority: 2] 192.0.2.18:52110 -> 10.0.0.30:80 TCP",
        "log_type": "network_intrusion",
        "severity": "high",
    },
    {
        "id": "fs-05",
        "text": "[**] [1:2018959:2] ET SCAN Suspicious inbound to mySQL port [**] [Classification: Attempted Information Leak] [Priority: 2] 198.51.100.55:3306 -> 10.0.0.11:3306 TCP",
        "log_type": "network_intrusion",
        "severity": "high",
    },
    # --- network_intrusion: medium ---
    {
        "id": "fs-06",
        "text": "[**] [1:2009582:4] ET POLICY Suspicious User-Agent Observed [**] [Classification: Potentially Bad Traffic] [Priority: 3] 203.0.113.60:49210 -> 10.0.0.5:80 TCP",
        "log_type": "network_intrusion",
        "severity": "medium",
    },
    {
        "id": "fs-07",
        "text": "[**] [1:2013028:3] ET POLICY Outdated TLS version used [**] [Classification: Potentially Bad Traffic] [Priority: 3] 198.51.100.21:51410 -> 10.0.0.19:443 TCP",
        "log_type": "network_intrusion",
        "severity": "medium",
    },
    # --- network_intrusion: low ---
    {
        "id": "fs-08",
        "text": "[**] [1:2001219:5] ET INFO External IP Lookup Service Query [**] [Classification: Not Suspicious Traffic] [Priority: 4] 10.0.0.40:52110 -> 198.51.100.2:443 TCP",
        "log_type": "network_intrusion",
        "severity": "low",
    },
    {
        "id": "fs-09",
        "text": "[**] [1:2000419:2] ET INFO DNS Query to a *.info domain [**] [Classification: Not Suspicious Traffic] [Priority: 4] 10.0.0.41:53210 -> 203.0.113.70:53 UDP",
        "log_type": "network_intrusion",
        "severity": "low",
    },
    # --- resource_anomaly: critical ---
    {
        "id": "fs-10",
        "text": "{\"alarm\": \"disk_full\", \"host\": \"db-prod-03\", \"status\": \"CRITICAL\", \"value\": 99.1, \"units\": \"%\", \"anomaly_rate\": 0.91, \"info\": \"root filesystem nearly full, writes failing\"}",
        "log_type": "resource_anomaly",
        "severity": "critical",
    },
    {
        "id": "fs-11",
        "text": "{\"alarm\": \"oom_kill_rate\", \"host\": \"worker-07\", \"status\": \"CRITICAL\", \"value\": 14, \"units\": \"kills/min\", \"anomaly_rate\": 0.95, \"info\": \"out-of-memory killer repeatedly terminating the main service process\"}",
        "log_type": "resource_anomaly",
        "severity": "critical",
    },
    # --- resource_anomaly: high ---
    {
        "id": "fs-12",
        "text": "{\"alarm\": \"swap_usage\", \"host\": \"web-prod-02\", \"status\": \"WARNING\", \"value\": 82.4, \"units\": \"%\", \"anomaly_rate\": 0.6, \"info\": \"swap usage elevated for the last 30 minutes, latency climbing\", \"error\": \"response_time_sla_breach\"}",
        "log_type": "resource_anomaly",
        "severity": "high",
    },
    {
        "id": "fs-13",
        "text": "{\"alarm\": \"queue_depth\", \"host\": \"worker-queue-01\", \"status\": \"WARNING\", \"value\": 5400, \"units\": \"jobs\", \"anomaly_rate\": 0.55, \"info\": \"error rate on job processing has tripled in the last 10 minutes\"}",
        "log_type": "resource_anomaly",
        "severity": "high",
    },
    # --- resource_anomaly: medium ---
    {
        "id": "fs-14",
        "text": "{\"alarm\": \"network_errors\", \"host\": \"edge-lb-01\", \"status\": \"WARNING\", \"value\": 120, \"units\": \"errors/min\", \"anomaly_rate\": 0.4, \"info\": \"packet retransmit rate above normal baseline\"}",
        "log_type": "resource_anomaly",
        "severity": "medium",
    },
    {
        "id": "fs-15",
        "text": "{\"alarm\": \"cpu_steal\", \"host\": \"vm-host-09\", \"status\": \"WARNING\", \"value\": 18.2, \"units\": \"%\", \"anomaly_rate\": 0.35, \"info\": \"hypervisor CPU steal time elevated, possible noisy neighbor\"}",
        "log_type": "resource_anomaly",
        "severity": "medium",
    },
    # --- resource_anomaly: low ---
    {
        "id": "fs-16",
        "text": "{\"alarm\": \"disk_io_wait\", \"host\": \"backup-01\", \"status\": \"CLEARED\", \"value\": 2.1, \"units\": \"%\", \"anomaly_rate\": 0.05, \"info\": \"notice: I/O wait returned to normal after nightly backup job completed\"}",
        "log_type": "resource_anomaly",
        "severity": "low",
    },
    {
        "id": "fs-17",
        "text": "{\"alarm\": \"cert_expiry\", \"host\": \"api-gateway-01\", \"status\": \"CLEARED\", \"value\": 45, \"units\": \"days\", \"anomaly_rate\": 0.02, \"info\": \"notice: certificate renewal completed, expiry window back to normal\"}",
        "log_type": "resource_anomaly",
        "severity": "low",
    },
    # --- unknown / unrecognized ---
    {
        "id": "fs-18",
        "text": "2026-11-01 09:14:02 INFO Scheduled job 'nightly_report' completed in 4.2s with no errors.",
        "log_type": "unknown",
        "severity": "low",
    },
]

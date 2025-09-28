# mitre_mapping.py
# A minimal rule-based mapping from keywords to MITRE tactics + short descriptions.
# Expand this with the official MITRE JSON or more rules as you go.

MITRE_RULES = [
    # (keyword, tactic_name, short_description)
    ("failed login", "Credential Access", "Repeated failed authentication attempts"),
    ("invalid login", "Credential Access", "Invalid authentication attempts"),
    ("consolelogin", "Initial Access", "Console login event; may indicate interactive access"),
    ("console_login", "Initial Access", "Console login event; may indicate interactive access"),
    ("unauthorized", "Privilege Escalation", "Unauthorized change or access attempt"),
    ("createpolicy", "Privilege Escalation", "IAM policy creation or modification"),
    ("iampolicy", "Privilege Escalation", "IAM policy creation or modification"),
    ("iam", "Privilege Escalation", "IAM-related event"),
    ("instance-launch", "Persistence", "New instance launch can indicate persistence mechanisms"),
    ("portscan", "Reconnaissance", "Network scanning to discover services"),
    ("port scan", "Reconnaissance", "Network scanning to discover services"),
    ("malware", "Execution", "Malware detected - code execution"),
    ("s3:GetObject", "Impact", "S3 access could lead to data exfiltration"),
    ("delete", "Impact", "Delete operations might indicate data removal"),
    ("aws:iam", "Privilege Escalation", "IAM events"),
]

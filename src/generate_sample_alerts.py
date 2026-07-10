import json
from pathlib import Path


OUTPUT_DIR = Path("knowledge_base/sample_alerts")


SAMPLE_ALERTS = {
    "brute_force_low_01.json": {
        "alert_id": "BF-LOW-001",
        "category": "brute_force",
        "risk_level": "low",
        "title": "Small number of failed VPN login attempts",
        "description": "A user had a small number of failed VPN login attempts and no successful login after the failures.",
        "user": "employee01",
        "account_type": "standard_user",
        "destination_system": "vpn-gateway",
        "source_ip": "10.10.5.24",
        "source_ip_type": "internal",
        "failed_attempt_count": 4,
        "time_window_minutes": 10,
        "success_after_failures": False,
        "login_status": "failed",
        "mfa_status": "not_triggered",
        "geo_location": "expected_location",
        "user_agent": "known_device",
        "business_hours": True,
        "notes": [
            "Low number of failed attempts",
            "No successful login after failures",
            "Internal source IP",
            "Could be normal user password mistake"
        ]
    },

    "brute_force_medium_01.json": {
        "alert_id": "BF-MED-001",
        "category": "brute_force",
        "risk_level": "medium",
        "title": "Multiple failed login attempts followed by successful VPN login",
        "description": "Multiple failed login attempts were detected for the admin user on the VPN gateway. After the failed attempts, a successful login was observed.",
        "user": "admin",
        "account_type": "privileged_user",
        "destination_system": "vpn-gateway",
        "source_ip": "192.168.1.25",
        "source_ip_type": "internal_or_unknown",
        "failed_attempt_count": 35,
        "time_window_minutes": 5,
        "success_after_failures": True,
        "login_status": "success_after_failures",
        "mfa_status": "unknown",
        "geo_location": "unknown",
        "user_agent": "unknown",
        "business_hours": True,
        "notes": [
            "Privileged account targeted",
            "High number of failed attempts in short time",
            "Successful login after failures",
            "MFA and post-login activity are unknown"
        ]
    },

    "brute_force_high_01.json": {
        "alert_id": "BF-HIGH-001",
        "category": "brute_force",
        "risk_level": "high",
        "title": "Privileged VPN login after repeated failures from unusual external IP",
        "description": "A privileged account had repeated failed VPN login attempts from an unusual external IP. A successful login followed, and suspicious post-login activity was observed.",
        "user": "domain_admin01",
        "account_type": "privileged_user",
        "destination_system": "vpn-gateway",
        "source_ip": "203.0.113.45",
        "source_ip_type": "external",
        "failed_attempt_count": 68,
        "time_window_minutes": 7,
        "success_after_failures": True,
        "login_status": "success_after_failures",
        "mfa_status": "mfa_push_accepted_unconfirmed",
        "geo_location": "unusual_location",
        "user_agent": "new_device",
        "business_hours": False,
        "post_login_activity": [
            "internal_rdp_connection",
            "privileged_resource_access",
            "security_group_query"
        ],
        "notes": [
            "Privileged account targeted",
            "External unusual source IP",
            "Successful login after repeated failures",
            "MFA approval not yet confirmed by user",
            "Suspicious post-login activity observed"
        ]
    },

    "phishing_low_01.json": {
        "alert_id": "PH-LOW-001",
        "category": "phishing",
        "risk_level": "low",
        "title": "User-reported suspicious email blocked by mail gateway",
        "description": "A user reported a suspicious email. The email was quarantined by the mail gateway and was not delivered to the inbox.",
        "sender_email": "newsletter@example.com",
        "sender_display_name": "Newsletter Service",
        "recipient": "employee02@company.local",
        "subject": "Monthly product update",
        "delivery_status": "quarantined",
        "spf_result": "pass",
        "dkim_result": "pass",
        "dmarc_result": "pass",
        "url_present": True,
        "url": "https://example.com/newsletter",
        "attachment_present": False,
        "user_clicked": False,
        "credentials_entered": False,
        "attachment_opened": False,
        "same_email_seen_in_other_mailboxes": False,
        "notes": [
            "Email was quarantined",
            "No user click observed",
            "No credentials entered",
            "Authentication results passed"
        ]
    },

    "phishing_medium_01.json": {
        "alert_id": "PH-MED-001",
        "category": "phishing",
        "risk_level": "medium",
        "title": "Suspicious password reset email with unknown link",
        "description": "A user reported a suspicious email with an urgent password reset subject. The email contains an unknown link. User click and credential entry status are unknown.",
        "sender_email": "security-alert@example-support.com",
        "sender_display_name": "IT Security Team",
        "reply_to": "helpdesk-reset@example-mail.com",
        "recipient": "employee03@company.local",
        "subject": "Urgent Password Reset Required",
        "delivery_status": "delivered",
        "spf_result": "softfail",
        "dkim_result": "none",
        "dmarc_result": "fail",
        "url_present": True,
        "url": "https://example-support.com/reset",
        "visible_link_text": "Reset Password",
        "attachment_present": False,
        "user_clicked": "unknown",
        "credentials_entered": "unknown",
        "attachment_opened": False,
        "same_email_seen_in_other_mailboxes": "unknown",
        "notes": [
            "Urgent password reset theme",
            "Unknown link",
            "DMARC failed",
            "User interaction status unknown"
        ]
    },

    "phishing_high_01.json": {
        "alert_id": "PH-HIGH-001",
        "category": "phishing",
        "risk_level": "high",
        "title": "Credential phishing with user click and suspicious login after submission",
        "description": "A phishing email led the user to a fake login page. The user clicked the link and reported entering credentials. A suspicious successful login was observed shortly after.",
        "sender_email": "admin@example-login.com",
        "sender_display_name": "Microsoft Security",
        "reply_to": "support@example-login.com",
        "recipient": "finance.user@company.local",
        "subject": "Security Alert: Verify Your Account",
        "delivery_status": "delivered",
        "spf_result": "fail",
        "dkim_result": "fail",
        "dmarc_result": "fail",
        "url_present": True,
        "url": "https://example-login.com/verify",
        "visible_link_text": "Verify Account",
        "landing_page_behavior": "fake_login_page",
        "attachment_present": False,
        "user_clicked": True,
        "credentials_entered": True,
        "attachment_opened": False,
        "suspicious_login_after_click": True,
        "same_email_seen_in_other_mailboxes": True,
        "affected_mailboxes_count": 14,
        "notes": [
            "User clicked the phishing link",
            "User reported entering credentials",
            "Suspicious login observed after click",
            "Multiple users received similar email",
            "Email authentication failed"
        ]
    },

    "powershell_low_01.json": {
        "alert_id": "PS-LOW-001",
        "category": "suspicious_powershell",
        "risk_level": "low",
        "title": "PowerShell execution by known IT management agent",
        "description": "PowerShell was executed by a known software deployment tool during business hours. No suspicious network connection or child process was observed.",
        "hostname": "WIN-CLIENT-07",
        "user": "system",
        "user_type": "service_account",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -File C:\\ProgramData\\CompanyAgent\\inventory.ps1",
        "parent_process": "company_management_agent.exe",
        "encoded_command_present": False,
        "network_connection": False,
        "destination_ip": None,
        "destination_domain": None,
        "file_created": False,
        "registry_change": False,
        "scheduled_task_created": False,
        "edr_alert": "informational",
        "business_hours": True,
        "notes": [
            "Known management agent parent process",
            "No encoded command",
            "No suspicious network connection",
            "No suspicious child process"
        ]
    },

    "powershell_medium_01.json": {
        "alert_id": "PS-MED-001",
        "category": "suspicious_powershell",
        "risk_level": "medium",
        "title": "Encoded PowerShell command by standard user",
        "description": "A standard user executed an encoded PowerShell command. Parent process and network connection status are unknown.",
        "hostname": "WIN-CLIENT-01",
        "user": "employee04",
        "user_type": "standard_user",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand <encoded_content_redacted>",
        "parent_process": "unknown",
        "encoded_command_present": True,
        "network_connection": "unknown",
        "destination_ip": "unknown",
        "destination_domain": "unknown",
        "file_created": "unknown",
        "registry_change": "unknown",
        "scheduled_task_created": "unknown",
        "edr_alert": "medium",
        "business_hours": True,
        "notes": [
            "Encoded PowerShell command",
            "Standard user context",
            "Parent process unknown",
            "Network connection status unknown",
            "More evidence required"
        ]
    },

    "powershell_high_01.json": {
        "alert_id": "PS-HIGH-001",
        "category": "suspicious_powershell",
        "risk_level": "high",
        "title": "PowerShell launched after email attachment with suspicious network connection",
        "description": "PowerShell was launched from an Office parent process after a user opened an email attachment. The process created a file and connected to an unusual external domain.",
        "hostname": "WIN-FINANCE-03",
        "user": "finance.user",
        "user_type": "standard_user",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand <encoded_content_redacted>",
        "parent_process": "winword.exe",
        "encoded_command_present": True,
        "network_connection": True,
        "destination_ip": "198.51.100.77",
        "destination_domain": "update-example.net",
        "url": "https://update-example.net/content",
        "file_created": True,
        "file_path": "C:\\Users\\finance.user\\AppData\\Local\\Temp\\update.tmp",
        "registry_change": "unknown",
        "scheduled_task_created": True,
        "edr_alert": "high",
        "related_phishing_alert": True,
        "business_hours": True,
        "notes": [
            "Office parent process launched PowerShell",
            "Encoded command present",
            "External network connection observed",
            "File created in Temp directory",
            "Scheduled task created",
            "Related phishing alert exists"
        ]
    }
}


def write_json_file(file_name, data):
    output_path = OUTPUT_DIR / file_name

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)

    print(f"Created: {output_path}")


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Generating CyberSOC sample alerts...")
    print("=" * 60)

    for file_name, data in SAMPLE_ALERTS.items():
        write_json_file(file_name, data)

    print("=" * 60)
    print(f"Done. Total sample alerts created: {len(SAMPLE_ALERTS)}")


if __name__ == "__main__":
    main()
    
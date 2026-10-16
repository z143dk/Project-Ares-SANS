import time
import subprocess
import os

# Adjust this path for local windows / wsl testing
LOG_PATH = "C:\\Users\\z143d\\Desktop\\Project-Ares-SANS\\config\\gateway.log"

def alert_antigravity(log_entry):
    print(f"🚨 THREAT DETECTED: {log_entry}")
    # In reality, this would invoke the AG CLI or Gemini API
    print("Invoking Antigravity 'security_audit' skill...")

def start_sentry():
    print("🛡️ Project Talos Sentry Active. Monitoring NemoClaw...")
    # Creating a dummy log file if it doesn't exist so we can tail it
    if not os.path.exists(LOG_PATH):
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'w') as f:
            f.write("NemoClaw Gateway Log Initialized.\n")

    # Tail the log file for policy violations
    # Use powershell tail equivalent in windows
    cmd = ["powershell", "-Command", f"Get-Content -Path '{LOG_PATH}' -Wait"]
    try:
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True) as tail:
            for line in tail.stdout:
                if "DENY" in line or "policy_violation" in line:
                    alert_antigravity(line.strip())
    except KeyboardInterrupt:
        print("Shutting down sentry...")

if __name__ == "__main__":
    start_sentry()

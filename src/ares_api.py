import os
import subprocess
import paramiko
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

# Setup directories
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI_DIR = os.path.join(ROOT_DIR, "ui")

app = Flask(__name__, static_folder=UI_DIR)
CORS(app)

VBOXMANAGE_PATH = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
VM_NAME = "vm"

@app.route('/')
def index():
    """Serve the Ares dashboard"""
    return send_from_directory(UI_DIR, 'ares.html')

@app.route('/api/vm/status', methods=['GET'])
def vm_status():
    """Check if the VirtualBox VM is running"""
    try:
        # VBoxManage showvminfo "vm" --machinereadable
        result = subprocess.run(
            [VBOXMANAGE_PATH, "showvminfo", VM_NAME, "--machinereadable"],
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            return jsonify({"status": "error", "message": "VM not found or VBoxManage failed."})
            
        output = result.stdout
        is_running = "VMState=\"running\"" in output
        
        return jsonify({
            "status": "success",
            "state": "running" if is_running else "stopped"
        })
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "VBoxManage not found. Is VirtualBox installed?"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/vm/start', methods=['POST'])
def vm_start():
    """Start the VirtualBox VM"""
    try:
        # Check if already running first
        status_res = subprocess.run([VBOXMANAGE_PATH, "showvminfo", VM_NAME, "--machinereadable"], capture_output=True, text=True)
        if "VMState=\"running\"" in status_res.stdout:
            return jsonify({"status": "success", "message": "VM is already running."})
            
        # Start headless or gui? GUI is usually preferred so they can see it if needed, but headless is cleaner.
        # Let's use gui for the hackathon so they can see the boot process.
        subprocess.Popen([VBOXMANAGE_PATH, "startvm", VM_NAME, "--type", "gui"])
        return jsonify({"status": "success", "message": "Boot sequence initiated for SIFT VM."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/vm/install', methods=['POST'])
def vm_install():
    """SSH into the VM and install Protocol SIFT"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to the local port forward we set up earlier (2222 -> 22)
        ssh.connect('127.0.0.1', port=2222, username='sansforensics', password='forensics', timeout=10)
        
        command = "curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash"
        stdin, stdout, stderr = ssh.exec_command(command)
        
        # Wait for the command to complete
        exit_status = stdout.channel.recv_exit_status()
        
        out = stdout.read().decode('utf-8')
        err = stderr.read().decode('utf-8')
        
        ssh.close()
        
        if exit_status == 0:
            return jsonify({
                "status": "success", 
                "message": "Protocol SIFT installed successfully inside VM.",
                "logs": out
            })
        else:
            return jsonify({
                "status": "error",
                "message": f"Installation failed with exit code {exit_status}",
                "logs": err + "\n" + out
            }), 500
            
    except paramiko.ssh_exception.AuthenticationException:
         return jsonify({"status": "error", "message": "SSH Authentication failed. Is the password still 'forensics'?"}), 500
    except Exception as e:
         return jsonify({"status": "error", "message": f"SSH connection failed. Ensure the VM is fully booted: {str(e)}"}), 500

@app.route('/api/triage/analyze', methods=['GET'])
def triage_analyze():
    """Run USB triage analysis logic directly on the mounted D drive"""
    try:
        report_dir = r"D:\Ares_Forensics_Report_20260516_132151"
        if not os.path.exists(report_dir):
            return jsonify({"status": "error", "message": "Forensics report directory not found on D: drive."}), 404

        import csv
        import json
        processes_file = os.path.join(report_dir, "processes.csv")
        network_file = os.path.join(report_dir, "network_connections.txt")
        
        process_map = {}
        if os.path.exists(processes_file):
            enc = 'utf-16' if os.path.getsize(processes_file) > 100 and b'\xff\xfe' in open(processes_file, 'rb').read(2) else 'utf-8-sig'
            with open(processes_file, 'r', encoding=enc) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    pid = row.get("ProcessId")
                    if pid:
                        process_map[pid] = {
                            "name": row.get("Name", "Unknown"),
                            "cmd": row.get("CommandLine", ""),
                            "path": row.get("ExecutablePath", ""),
                            "parent": row.get("ParentProcessId", "")
                        }

        connections = []
        anomalies = []
        false_positives = []
        safe_keywords = ["surfshark", "tailscale", "proton", "mullvad", "windscribe", "avast", "malwarebytes", "mcafee"]

        if os.path.exists(network_file):
            enc = 'utf-16' if b'\xff\xfe' in open(network_file, 'rb').read(2) else 'utf-8-sig'
            with open(network_file, 'r', encoding=enc) as f:
                for line in f:
                    if "CLOSE_WAIT" in line or "ESTABLISHED" in line:
                        parts = line.strip().split()
                        if len(parts) >= 5:
                            proto, local, foreign, state, pid = parts[0], parts[1], parts[2], parts[3], parts[4]
                            proc_info = process_map.get(pid, {"name": "Unknown", "path": "", "cmd": ""})
                            conn_data = {
                                "proto": proto, "local": local, "foreign": foreign, "state": state, "pid": pid,
                                "proc_name": proc_info["name"], "proc_path": proc_info["path"]
                            }
                            connections.append(conn_data)
                            is_safe = any(kw in proc_info["name"].lower() or kw in proc_info["path"].lower() or kw in proc_info["cmd"].lower() for kw in safe_keywords)
                            if is_safe:
                                false_positives.append(conn_data)
                            elif proc_info["name"] != "Unknown":
                                if "temp" in proc_info["path"].lower() or "appdata" in proc_info["path"].lower():
                                    anomalies.append(conn_data)

        return jsonify({
            "status": "success",
            "total_connections": len(connections),
            "anomalies_count": len(anomalies),
            "false_positives_count": len(false_positives),
            "anomalies": anomalies,
            "false_positives": false_positives
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    print(f"Project Ares API Dashboard starting on http://localhost:5051")
    app.run(host='0.0.0.0', port=5051, debug=True)

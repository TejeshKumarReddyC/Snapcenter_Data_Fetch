import requests
import urllib3
import csv
import getpass
import paramiko
import pandas as pd
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import StringIO

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =============================
# Function 1: Fetch SnapCenter Hosts
# =============================
def fetch_snapcenter_hosts(username, password):
    fieldnames = [
        "HostId", "HostName", "DomainName", "IP", "OperatingSystem", "HypervisorType",
        "RunAsName", "UserName", "Status", "Issues", "SnapCenterURL"
    ]
    all_hosts = []

    #  Hardcoded SnapCenter URLs
    snapcenter_urls = [
        "https://host1.example.com:8146/", 
        "https://host2.example.com:8146/", 
        #Add more here if required
    ]

    for snapcenter_url in snapcenter_urls:
        print(f"\nFetching hosts from SnapCenter: {snapcenter_url}/")
        login_url = f"{snapcenter_url}/api/6.1/auth/login?TokenNeverExpires=true"
        payload = {"UserOperationContext": {"User": {"Name": username, "Passphrase": password, "Rolename": "SnapCenterAdmin"}}}
        headers = {"accept": "application/json", "Content-Type": "application/json"}

        try:
            auth_resp = requests.post(login_url, headers=headers, json=payload, verify=False)
            auth_data = auth_resp.json()
            token = auth_data.get("User", {}).get("Token")
            if not token:
                print(f"Token not found for {snapcenter_url}, skipping...")
                continue
        except Exception as e:
            print(f"Error logging in to {snapcenter_url}: {e}")
            continue

        hosts_url = f"{snapcenter_url}/api/6.1/hosts?IncludePluginInfo=false&IncludeVerificationServerInfo=false"
        headers = {"accept": "application/json", "Token": token}

        try:
            resp = requests.get(hosts_url, headers=headers, verify=False)
            if resp.status_code != 200:
                continue
            data = resp.json()
            hosts = data.get("HostInfo", {}).get("Hosts", [])
        except Exception as e:
            print(f"Error fetching hosts from {snapcenter_url}: {e}")
            continue

        for h in hosts:
            host_info = {
                "HostId": h.get("HostId"),
                "HostName": h.get("HostName", "").split(".")[0],
                "DomainName": h.get("DomainName"),
                "IP": h.get("IPs", [{}])[0].get("Value") if h.get("IPs") else "",
                "OperatingSystem": h.get("OsInfo", {}).get("OperatingSystemName"),
                "HypervisorType": h.get("HypervisorType"),
                "RunAsName": h.get("Auth", {}).get("RunAsName"),
                "UserName": h.get("Auth", {}).get("UserName"),
                "Status": h.get("OverallStatus", {}).get("Status"),
                "Issues": h.get("OverallStatus", {}).get("Issues", "").replace("\r\n", "; "),
                "SnapCenterURL": snapcenter_url
            }
            all_hosts.append(host_info)

    print(f"\nSnapCenter host data fetched: {len(all_hosts)} hosts")
    return all_hosts

# =============================
# Function 2: SSH Connection
# =============================
def ssh_connect(host, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, username=username, password=password, timeout=30)
        return ssh
    except Exception as e:
        print(f"SSH connection failed for {host}: {e}")
        return None

# =============================
# Function 3: Run full command
# =============================
def run_full_command(ssh, command):
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode(errors="ignore")
    error = stderr.read().decode(errors="ignore")
    return output + ("\n" + error if error else "")

# =============================
# Function 4: Run single NetApp command
# =============================
def run_single_netapp_command(host, username, password, name, command):
    ssh = ssh_connect(host, username, password)
    if not ssh:
        return name, ""

    print(f"\n Running command: {name}")
    output = run_full_command(ssh, command)
    ssh.close()
    print(f"Completed: {name} ({len(output.splitlines())} lines)")
    return name, output

# =============================
# Function 5: Run NetApp commands in parallel
# =============================
def run_netapp_commands_parallel(host, username, password):
    commands = {
        "NFS": f'export SSHPASS="{password}"; for i in `cat /data/output/netapp/inv_lists/clusters.list`; do echo $i; sshpass -e ssh -q -o StrictHostKeyChecking=no -l "mgmt\\\\{username}" $i export-policy rule show -fields clientmatch; done',
        "ISCSI": f'export SSHPASS="{password}"; for i in `cat /data/output/netapp/inv_lists/clusters.list`; do echo $i; sshpass -e ssh -q -o StrictHostKeyChecking=no -l "mgmt\\\\{username}" $i igroup show -fields initiator; done',
        "CifsShares": f'export SSHPASS="{password}"; for i in `cat /data/output/netapp/inv_lists/clusters.list`; do echo $i; sshpass -e ssh -q -o StrictHostKeyChecking=no -l "mgmt\\\\{username}" $i cifs share show -fields share-name,path; done'
    }

    results = {}
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_to_name = {executor.submit(run_single_netapp_command, host, username, password, name, cmd): name for name, cmd in commands.items()}
        for future in as_completed(future_to_name):
            name, output = future.result()
            results[name] = output
    return results

# =============================
# Function 6: Save all results to Excel
# =============================
def save_all_results_to_excel(results, snapcenter_data):
    filename = f"storage_results_{int(time.time())}.xlsx"
    print(f"\nSaving results to {filename}...")

    with pd.ExcelWriter(filename, engine="xlsxwriter") as writer:
        # Save NetApp command results
        for sheet_name, content in results.items():
            lines = [line for line in content.strip().splitlines() if line.strip()]
            if not lines:
                continue

            if sheet_name == "NFS":
                headers = ["vserver", "policyname", "ruleindex", "clientmatch"]
            elif sheet_name == "ISCSI":
                headers = ["vserver", "igroup", "initiator"]
            else:
                headers = ["vserver", "share-name", "path"]

            parsed_rows = []
            for line in lines:
                parts = line.split()
                if len(parts) < len(headers):
                    parts += [""] * (len(headers) - len(parts))
                elif len(parts) > len(headers):
                    parts = parts[:len(headers)]
                parsed_rows.append(parts)

            df = pd.DataFrame(parsed_rows, columns=headers)
            df.to_excel(writer, sheet_name=sheet_name, index=False)

        # Save SnapCenter hosts to a separate sheet
        if snapcenter_data:
            df_snap = pd.DataFrame(snapcenter_data)
            df_snap.to_excel(writer, sheet_name="SnapCenterHosts", index=False)

    print("All results saved successfully with SnapCenter data included!")

# =============================
# MAIN PROGRAM
# =============================
if __name__ == "__main__":
    # SnapCenter credentials
    user = input("Enter your username (without 'mgmt\\'): ").strip()
    username = r"mgmt\\" + user
    password = getpass.getpass("Enter your mgmt password: ").strip()

    # Remote host for NetApp
    remote_host = "jump_server_IP"

    # 1. Run NetApp loops in parallel
    netapp_results = run_netapp_commands_parallel(remote_host, user, password)

    # 2. Fetch SnapCenter data
    snapcenter_data = fetch_snapcenter_hosts(username, password)

    # 3. Save all results to a single Excel file
    save_all_results_to_excel(netapp_results, snapcenter_data)

    print("\nAll operations completed successfully!")

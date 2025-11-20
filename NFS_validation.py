#!/usr/bin/env python3
import paramiko
import getpass
import csv
import re
from datetime import datetime

INPUT_FILE = "vservers.csv"  # CSV input
JUMP_HOST = "10.17.64.27"
JUMP_USER = "mc292242"

IGNORED_CLIENT_TOKENS = {
    "query.",
    "jump1.example.com",
    "jump2.example.com",
}
# === NEW: normalization to treat domain variants as same ===
def normalize_clientmatch(c):
    if not c:
        return c
    c = c.lower().strip()
    if c.endswith(".com"):
        c = c[:-4]
    return c

last_vserver_written = None

def log_append(fp, msg, results_fp=None):
    global last_vserver_written
    print(msg)
    # Write to main log
    fp.write(msg + "\n")
    fp.flush()

    # Handle RESULT formatting
    if results_fp and msg.strip().startswith("==> RESULT:"):
        # Extract the vserver name after "==> RESULT:"
        try:
            vserver = msg.split("|")[0].replace("==> RESULT:", "").strip()
        except:
            vserver = None
        # Add blank line *before* new vserver block
        if last_vserver_written and vserver != last_vserver_written:
            results_fp.write("\n")
        results_fp.write(msg + "\n")
        results_fp.flush()
        last_vserver_written = vserver

def ssh_connect(host, username, password, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=password, timeout=timeout)
    return client

def run_command(ssh_client, cmd, timeout=300):
    stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode(errors="ignore")
    err = stderr.read().decode(errors="ignore")
    return (out + ("\n" + err if err else "")).strip()

def run_check(ssh_client, cmd, f_log, context=None, timeout=300):
    """
    Checking command: log only the command (no output printed or logged),
    but return output for internal decision-making.
    """
    if context:
        f_log.write(f"\n[{context}] {cmd}\n")
    else:
        f_log.write(f"\n[CHECK] {cmd}\n")
    f_log.flush()
    output = run_command(ssh_client, cmd, timeout=timeout)
    return output

def run_fetch(ssh_client, cmd, f_log, context=None, timeout=300):
    """
    Fetching command: log the command and also log & print its output.
    """
    if context:
        f_log.write(f"\n[{context}] {cmd}\n")
    else:
        f_log.write(f"\n[FETCH] {cmd}\n")
    f_log.flush()

    output = run_command(ssh_client, cmd, timeout=timeout)
    if output:
        for line in output.splitlines():
            f_log.write(line + "\n")
    else:
        f_log.write("(no output)\n")
    f_log.flush()
    return output

# === CSV PARSING ===
def parse_input_global_clients(filename):
    """
    Returns:
      - global_clients: set(all clientmatches found in CSV) normalized
      - vserver_policies: dict { vserver: set(policyname, ...) }
      - policy_to_clients: dict { policyname_lower: set(clientmatches) }
    """
    clients = set()
    vserver_policies = {}
    policy_to_clients = {}
    with open(filename, "r", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames:
            reader.fieldnames = [h.strip().lower() for h in reader.fieldnames]
        for row in reader:
            row = { (k.strip().lower() if k else k): (v.strip() if isinstance(v, str) else v)
                    for k, v in row.items() }
            v = row.get("vserver", "")
            p = (row.get("policyname", "") or "")
            c = (row.get("clientmatch", "") or "")
            if c:
                c_low = c.lower().strip()
                if c_low and c_low not in IGNORED_CLIENT_TOKENS:
                    norm = normalize_clientmatch(c_low)
                    clients.add(norm)
                    # attach to the policy mapping
                    p_low = p.lower().strip()
                    if p_low:
                        if p_low not in policy_to_clients:
                            policy_to_clients[p_low] = set()
                        policy_to_clients[p_low].add(norm)
            if v:
                if v not in vserver_policies:
                    vserver_policies[v] = set()
                if p:
                    vserver_policies[v].add(p)
    return clients, vserver_policies, policy_to_clients

def parse_clientmatches_from_export_policy(output):
    found = set()
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        l = line.lower()
        if (
            l.startswith("last login")
            or l.startswith("vserver")
            or l.startswith("policyname")
            or l.startswith("ruleindex")
            or "entries were displayed" in l
            or re.match(r"^[\-\=_\s]+$", line)
        ):
            continue
        parts = re.split(r'\s+', line)
        if not parts:
            continue
        candidate = parts[-1].strip().lower()
        if (
            not candidate
            or candidate in ("clientmatch", "vserver", "policyname", "ruleindex")
            or candidate in IGNORED_CLIENT_TOKENS
        ):
            continue
        if "." in candidate or re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$', candidate):
            found.add(normalize_clientmatch(candidate))
    return found

# Helpers to parse qtree output and extract qtree names (3rd column) and export-policy (4th)
def parse_qtrees_and_export_policies_from_qtree_show(output):
    """
    Return list of tuples: (qtree_name_or_empty, export_policy_or_empty)
    Handles cases where the export-policy may be on the same row or on the following wrapped row.
    """
    if not output:
        return []

    lines = [ln.rstrip() for ln in output.splitlines()]
    # keep only non-empty lines but preserve their order for parsing
    nonempty = [ln for ln in lines if ln.strip()]

    # find header start index if present
    header_idx = None
    for idx, ln in enumerate(nonempty):
        low = ln.lower()
        if 'vserver' in low and 'volume' in low and 'qtree' in low:
            header_idx = idx
            break

    data_lines = nonempty[header_idx + 1:] if header_idx is not None else nonempty

    parsed = []
    # We'll try to extract columns by splitting on 2+ spaces, but be defensive
    idx = 0
    while idx < len(data_lines):
        ln = data_lines[idx]
        # skip separator lines
        if re.match(r'^[-=_\s]+$', ln.strip()):
            idx += 1
            continue

        cols = re.split(r'\s{2,}', ln)
        # If there are less than 3 columns, try split on whitespace
        if len(cols) < 3:
            cols = re.split(r'\s+', ln.strip())
            if len(cols) < 3:
                # Might be a wrapped export-policy line (indented). Try to merge with previous.
                # If previous exists and we have an entry with empty export-policy, attach this as export-policy.
                # We'll handle this by attempting to parse next line as possibly export-policy-only.
                # For safety, attempt simple heuristic: if line starts with whitespace then it's a continuation.
                if ln.startswith(" ") or ln.startswith("\t"):
                    # attach to previous if previous had no export-policy
                    if parsed and not parsed[-1][1]:
                        ep = ln.strip()
                        prev_q, _ = parsed[-1]
                        parsed[-1] = (prev_q, ep)
                idx += 1
                continue

        # Now extract qtree (3rd column) and export-policy (4th column if present)
        qtree = ""
        export_policy = ""
        # cols may be: [vserver, volume, qtree, export-policy] or sometimes qtree field is "" and export-policy on same row
        if len(cols) >= 3:
            qtree = cols[2].strip().strip('"')
            if qtree.lower() == '""' or qtree.lower() == 'none':
                qtree = ""
        if len(cols) >= 4:
            export_policy = cols[3].strip()
        else:
            # Look ahead to next line: sometimes export-policy is displayed on the next physical line (indented)
            if idx + 1 < len(data_lines):
                next_ln = data_lines[idx + 1]
                # heuristic: export-policy-only lines often are indented or don't contain a vserver/volume/qtree pattern
                if not re.search(r'\S+\s+\S+\s+\S+', next_ln):
                    # treat the trimmed next line as possible export-policy
                    possible = next_ln.strip()
                    if possible:
                        export_policy = possible
                        idx += 1  # consume next line
        # If export_policy is '""' or 'none' treat as empty
        if export_policy.lower().strip() in ('', '""', 'none'):
            export_policy = ""

        parsed.append((qtree, export_policy))
        idx += 1

    # dedupe preserving order
    seen = set()
    deduped = []
    for q, e in parsed:
        key = (q, e)
        if key not in seen:
            deduped.append((q, e))
            seen.add(key)
    return deduped

def check_qtrees_against_global_using_export_policy(filer_client, vserver, qtree_policy_pairs, global_clients, f_log):
    """
    qtree_policy_pairs: list of (qtree, export_policy)
    For each pair, choose export_policy (if present) else qtree for the export-policy rule show check.
    Returns (ok_bool, list_of_reasons, set_of_external_clients)
    """
    reasons = []
    external_clients_accum = set()
    for q, ep in qtree_policy_pairs:
        policy_to_check = ep if ep else q
        if not policy_to_check:
            continue
        cmd = f"export-policy rule show -vserver {vserver} -policyname {policy_to_check} -fields clientmatch"
        out = run_check(filer_client, cmd, f_log=f_log, context=f"{vserver}:{policy_to_check} - export-policy (qtree/ep)")
        clients = parse_clientmatches_from_export_policy(out)
        clients_l = {normalize_clientmatch(x) for x in clients if x}
        if not clients_l:
            continue
        extra = clients_l - global_clients
        if extra:
            reasons.append(f"policy '{policy_to_check}' has external clientmatch: {', '.join(sorted(extra))}")
            external_clients_accum.update(extra)
    if external_clients_accum:
        return False, reasons, external_clients_accum
    return True, [], set()

def get_volume_state_from_output(output):
    if not output:
        return "unknown"
    for line in output.splitlines():
        ln = line.strip().lower()
        m = re.match(r'volume state:\s*(\S+)', ln)
        if m:
            return m.group(1)
        m2 = re.match(r'volume state\s+(\S+)', ln)
        if m2:
            return m2.group(1)
    for line in output.splitlines():
        m = re.search(r'\bstate:\s*(\S+)', line.lower())
        if m:
            return m.group(1)
    return "unknown"

def get_volume_state(filer_client, vserver, volume, f_log):
    cmd = f"volume show -vserver {vserver} -volume {volume}"
    out = run_check(filer_client, cmd, f_log=f_log, context=f"{vserver}:{volume} - volume show (check)")
    return get_volume_state_from_output(out)

def collect_vserver_data(filer_client, vserver, f_log):
    commands = {
        "Volume show": f"volume show -vserver {vserver}",
        "Export-policy rules": f"export-policy rule show -vserver {vserver} -policyname * -fields clientmatch",
        "CIFS shares": f"cifs share show -vserver {vserver}",
        "CIFS sessions": f"cifs session show -vserver {vserver}",
        "LUNs": f"lun show -vserver {vserver}",
        "SnapMirror destinations": f"snapmirror list-destinations -source-path {vserver}:*",
        "Export-policy show": f"export-policy show -vserver {vserver}",
        # Your existing ones (kept)
        #"Qtree relations": f"vol qtree show -vserver {vserver} -volume * -fields export-policy",
    }

    for desc, cmd in commands.items():
        run_fetch(
            filer_client,
            cmd,
            f_log=f_log,
            context=f"{vserver} - {desc}"
        )

def collect_volume_data(filer_client, vserver, volume, f_log):
    commands = {
        # 1. Vserver-level volume show
        "Volume show (vserver-level)": f"volume show -vserver {vserver}",

        # 2. All export policies in vserver
        "Export-policy rules (all policies)": (
            f"export-policy rule show -vserver {vserver} -policyname * -fields clientmatch"
        ),

        # 3. Export policy specific to this volume
        "Export-policy rules (volume policy)": (
            f"export-policy rule show -vserver {vserver} -policyname {volume} -fields clientmatch"
        ),

        # 4. Qtree relations
        "Qtree relations": (
            f"vol qtree show -vserver {vserver} -volume {volume} -fields export-policy"
        ),

        # 5. SnapMirror destinations (vserver-level)
        "SnapMirror destinations (all volumes)": (
            f"snapmirror list-destinations -source-path {vserver}:*"
        ),

        # Existing commands kept below
        #"CIFS shares": f"cifs share show -vserver {vserver}",
        #"CIFS sessions": f"cifs session show -vserver {vserver}",
        #"LUNs": f"lun show -vserver {vserver}",
        #"Volume state": f"volume show -vserver {vserver} -volume {volume}",
        #"SnapMirror destinations (specific volume)": (
        #   f"snapmirror list-destinations -source-path {vserver}:{volume}"
        #),
    }

    for desc, cmd in commands.items():
        run_fetch(
            filer_client,
            cmd,
            f_log=f_log,
            context=f"{vserver}:{volume} - {desc}"
        )

# ---- parse snapmirror output into pairs ----
def parse_snapmirror_pairs(output):
    pairs = []
    if not output:
        return pairs
    tokens = re.findall(r'([A-Za-z][^\s:]*:[^\s]+)', output)
    for i in range(0, len(tokens), 2):
        if i + 1 < len(tokens):
            src = tokens[i]
            dst = tokens[i+1]
            try:
                src_v, src_vol = src.split(":", 1)
                dst_v, dst_vol = dst.split(":", 1)
                pairs.append((src_v.strip(), src_vol.strip(), dst_v.strip(), dst_vol.strip()))
            except Exception:
                continue
    return pairs

def get_physical_filer_for_vserver(jump_client, vserver, f_log):
    cmd = f"cat /data/output/netapp/inv_lists/cdlist.list | grep -i {vserver}"
    out = run_check(jump_client, cmd, f_log=f_log, context=f"JumpHost - cdlist grep for {vserver}")
    if not out.strip():
        return None
    parts = out.split()
    if len(parts) >= 2:
        return parts[1]
    return None

def compare_snapmirror_qtrees(filer_client, jump_client, admin_pass, vserver, snap_out, f_log):
    pairs = parse_snapmirror_pairs(snap_out)
    reasons = []
    if not pairs:
        return True, []
    for src_v, src_vol, dst_v, dst_vol in pairs:
        src_cmd = f"vol qtree show -vserver {src_v} -volume {src_vol} -fields export-policy"
        src_out = run_fetch(filer_client, src_cmd, f_log=f_log, context=f"{vserver} - snap source qtree ({src_v}:{src_vol})")
        src_qtrees = set(parse_qtrees_and_export_policies_from_qtree_show(src_out))

        dest_physical = get_physical_filer_for_vserver(jump_client, dst_v, f_log)
        if not dest_physical:
            reasons.append(f"destination vserver {dst_v} physical filer not found in cdlist")
            return False, reasons

        try:
            transport = jump_client.get_transport()
            channel = transport.open_channel("direct-tcpip", (dest_physical, 22), (JUMP_HOST, 22))
            dest_client = paramiko.SSHClient()
            dest_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            dest_client.connect(dest_physical, username="admin", password=admin_pass, sock=channel)
            dst_cmd = f"vol qtree show -vserver {dst_v} -volume {dst_vol} -fields export-policy"
            dst_out = run_fetch(dest_client, dst_cmd, f_log=f_log, context=f"{vserver} - snap dest qtree ({dst_v}:{dst_vol})")
            dst_qtrees = set(parse_qtrees_and_export_policies_from_qtree_show(dst_out))
            dest_client.close()
        except Exception as e:
            reasons.append(f"failed to connect to destination physical filer {dest_physical} for {dst_v}: {e}")
            return False, reasons

        # compare qtree names (non-empty) equality
        src_qtrees_norm = {q for q, _ in src_qtrees if q}
        dst_qtrees_norm = {q for q, _ in dst_qtrees if q}

        if src_qtrees_norm != dst_qtrees_norm:
            reasons.append(
                f"qtrees mismatch for source {src_v}:{src_vol} -> dest {dst_v}:{dst_vol}: "
                f"src={sorted(src_qtrees_norm)} dst={sorted(dst_qtrees_norm)}"
            )
            return False, reasons

    return True, []

# ---- NEW: reconfirmation for volume ----
def reconfirm_volume_dedicated(filer_client, jump_client, admin_pass, vserver, volume, global_clients, f_log):
    reasons = []

    # i) qtree check for this specific volume
    qtree_cmd = f"vol qtree show -vserver {vserver} -volume {volume} -fields export-policy"
    qtree_out = run_fetch(filer_client, qtree_cmd, f_log=f_log, context=f"{vserver}:{volume} - qtree show (reconfirm)")
    qtree_out_l = (qtree_out or "").lower()
    if "there are no entries matching your query." in qtree_out_l or not qtree_out_l.strip():
        pass
    else:
        qtree_list = parse_qtrees_and_export_policies_from_qtree_show(qtree_out)
        if not qtree_list or all(q == "" for q, _ in qtree_list):
            pass
        else:
            non_empty_qtrees = [pair for pair in qtree_list if pair[0] or pair[1]]
            ok, q_reasons, _ = check_qtrees_against_global_using_export_policy(filer_client, vserver, non_empty_qtrees, global_clients, f_log)
            if not ok:
                reasons.extend(q_reasons)

    # ii) CIFS shares
    cifs_cmd = f"cifs share show -vserver {vserver}"
    cifs_out = run_fetch(filer_client, cifs_cmd, f_log=f_log, context=f"{vserver}:{volume} - cifs shares (reconfirm)")
    cifs_out_l = (cifs_out or "").lower()
    if not ("there are no entries matching your query." in cifs_out_l or not cifs_out_l.strip()):
        reasons.append("cifs shares present")

    # iii) LUNs
    lun_cmd = f"lun show -vserver {vserver}"
    lun_out = run_fetch(filer_client, lun_cmd, f_log=f_log, context=f"{vserver}:{volume} - luns (reconfirm)")
    lun_out_l = (lun_out or "").lower()
    if not ("there are no entries matching your query." in lun_out_l or not lun_out_l.strip()):
        reasons.append("luns present")

    # iv) snapmirror destinations
    snap_cmd = f"snapmirror list-destinations -source-path {vserver}:{volume}"
    snap_out = run_fetch(filer_client, snap_cmd, f_log=f_log, context=f"{vserver}:{volume} - snapmirror destinations (reconfirm)")
    snap_out_l = (snap_out or "").lower()
    if not ("there are no entries matching your query." in snap_out_l or not snap_out_l.strip()):
        ok, snap_reasons = compare_snapmirror_qtrees(filer_client, jump_client, admin_pass, vserver, snap_out, f_log)
        if not ok:
            reasons.extend(snap_reasons)

    if reasons:
        return False, reasons
    return True, []

def is_vserver_really_dedicated(filer_client, vserver, global_clients, jump_client, admin_pass, f_log):
    reasons = []

    qtree_cmd = f"vol qtree show -vserver {vserver} -volume * -fields export-policy"
    qtree_out = run_fetch(filer_client, qtree_cmd, f_log=f_log, context=f"{vserver} - qtree relations (reconfirm)")
    qtree_out_l = (qtree_out or "").lower()
    if "there are no entries matching your query." in qtree_out_l or not qtree_out_l.strip():
        pass
    else:
        qtree_list = parse_qtrees_and_export_policies_from_qtree_show(qtree_out)
        if all(q == "" for q, _ in qtree_list):
            pass
        else:
            non_empty_qtrees = [pair for pair in qtree_list if pair[0] or pair[1]]
            ok, q_reasons, _ = check_qtrees_against_global_using_export_policy(filer_client, vserver, non_empty_qtrees, global_clients, f_log)
            if not ok:
                reasons.extend(q_reasons)

    cifs_cmd = f"cifs share show -vserver {vserver}"
    cifs_out = run_fetch(filer_client, cifs_cmd, f_log=f_log, context=f"{vserver} - cifs shares (reconfirm)")
    cifs_out_l = (cifs_out or "").lower()
    if not ("there are no entries matching your query." in cifs_out_l or not cifs_out_l.strip()):
        reasons.append("cifs shares present")

    lun_cmd = f"lun show -vserver {vserver}"
    lun_out = run_fetch(filer_client, lun_cmd, f_log=f_log, context=f"{vserver} - luns (reconfirm)")
    lun_out_l = (lun_out or "").lower()
    if not ("there are no entries matching your query." in lun_out_l or not lun_out_l.strip()):
        reasons.append("luns present")

    snap_cmd = f"snapmirror list-destinations -source-path {vserver}:*"
    snap_out = run_fetch(filer_client, snap_cmd, f_log=f_log, context=f"{vserver} - snapmirror destinations (reconfirm)")
    snap_out_l = (snap_out or "").lower()
    if not ("there are no entries matching your query." in snap_out_l or not snap_out_l.strip()):
        ok, snap_reasons = compare_snapmirror_qtrees(filer_client, jump_client, admin_pass, vserver, snap_out, f_log)
        if not ok:
            reasons.extend(snap_reasons)

    if reasons:
        return False, reasons
    return True, []

# ---- NEW: Special logic for policies starting with als_ or infra_ (case-insensitive) ----
def special_policy_volume_check(filer_client, jump_client, admin_pass, vserver, policy, policy_to_clients, f_log):
    """
    Special policy-volume-qtree validation logic.

    Steps:
      1. Get volumes in the vserver.
      2. For each volume -> get qtrees.
      3. Find the volume whose qtree name == policy (case-insensitive).
      4. For that volume -> check clientmatches for every qtree's export-policy.
      5. If all qtrees' clients ⊆ policy CSV clients → DEDICATED VOLUME.
         Else SHARED VOLUME + list of external clients.
    """
    reasons = []
    p_low = policy.lower().strip()
    allowed_clients = policy_to_clients.get(p_low, set())

    # -------------------------------------------------------------
    # (1) FIXED VOLUME PARSING — supports single-space separated output
    # -------------------------------------------------------------
    vol_cmd = f"volume show -vserver {vserver}"
    vol_out = run_fetch(
        filer_client,
        vol_cmd,
        f_log=f_log,
        context=f"{vserver} - volume show (special logic)"
    )

    vol_lines = []

    for ln in (vol_out or "").splitlines():
        ln_strip = ln.strip()
        if (
            not ln_strip
            or ln_strip.startswith("----")
            or ln_strip.lower().startswith("vserver")
        ):
            continue

        # Regex: <Vserver> <Volume> <Aggregate> ...
        m = re.match(r'^(\S+)\s+(\S+)\s+(\S+)\s+', ln_strip)
        if not m:
            continue

        vol = m.group(2).strip()

        # Valid ONTAP volume name: must start with letter or underscore
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]+$', vol):
            vol_lines.append(vol)

    if not vol_lines:
        return "SHARED VOLUME", ["No volumes parsed from vserver"]

    # -------------------------------------------------------------
    # (2) Find the volume whose qtree == policy
    # -------------------------------------------------------------
    target_volume = None
    target_qtrees = []

    for vol in vol_lines:
        q_cmd = f"qtree show -vserver {vserver} -volume {vol} -fields export-policy"
        q_out = run_fetch(
            filer_client,
            q_cmd,
            f_log=f_log,
            context=f"{vserver}:{vol} - qtree show (special logic)"
        )

        qtrees = parse_qtrees_and_export_policies_from_qtree_show(q_out)

        for q, _ in qtrees:
            if q and q.lower() == p_low:
                target_volume = vol
                target_qtrees = qtrees
                break

        if target_volume:
            break

    if not target_volume:
        return "SHARED VOLUME", [f"policy '{policy}' not found as a qtree in any volume"]

    # -------------------------------------------------------------
    # (3) Validate export-policy rule show for each qtree
    # -------------------------------------------------------------
    all_ok = True
    extra_clients_accum = set()

    non_empty_qpairs = [pair for pair in target_qtrees if pair[0] or pair[1]]
    ok, reasons, extras = check_qtrees_against_global_using_export_policy(filer_client, vserver, non_empty_qpairs, set(allowed_clients), f_log)
    if not ok:
        all_ok = False
        extra_clients_accum.update(extras)

    # -------------------------------------------------------------
    # (4) Final classification
    # -------------------------------------------------------------
    if all_ok:
        return (
            "DEDICATED VOLUME",
            [
                f"volume '{target_volume}' contains policy '{policy}' and all qtree clients are within CSV allowed list"
            ]
        )

    else:
        reason = (
            f"volume '{target_volume}' contains qtrees with external clients: "
            f"{', '.join(sorted(extra_clients_accum)[:2])}"
        )
        return "SHARED VOLUME", [reason]

# === MAIN ===
if __name__ == "__main__":
    jump_pass = getpass.getpass("Enter jump server password: ")
    admin_pass = getpass.getpass("Enter admin password of physical filer: ")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"shared_check_all_{ts}.log"
    result_file = f"results_only_{ts}.log"

    f_log = open(log_file, "w")
    f_res = open(result_file, "w")

    log_append(f_log, f"NFS Validation run: {ts}", f_res)
    global_clients, vserver_policies, policy_to_clients = parse_input_global_clients(INPUT_FILE)
    # ensure global_clients normalized
    global_clients = {normalize_clientmatch(x) for x in global_clients if x}

    log_append(f_log, f"Global unique clientmatches ({len(global_clients)}):", f_res)
    for c in sorted(global_clients):
        log_append(f_log, f"  {c}", f_res)

    jump_client = ssh_connect(JUMP_HOST, JUMP_USER, jump_pass)

    for vserver, input_policies in vserver_policies.items():
        log_append(f_log, f"\nProcessing vserver: {vserver}", f_res)

        cd_cmd = f"cat /data/output/netapp/inv_lists/cdlist.list | grep -i {vserver}"
        cd_out = run_check(jump_client, cd_cmd, f_log=f_log, context="JumpHost - cdlist grep")

        if not cd_out.strip():
            log_append(f_log, f"[WARN] No cdlist entry for {vserver}", f_res)
            continue

        parts = cd_out.split()
        if len(parts) < 2:
            log_append(f_log, f"[WARN] Unexpected cdlist format: {cd_out}", f_res)
            continue

        physical_filer = parts[1]
        log_append(f_log, f"Physical filer: {physical_filer}", f_res)

        try:
            transport = jump_client.get_transport()
            channel = transport.open_channel("direct-tcpip", (physical_filer, 22), (JUMP_HOST, 22))
            filer_client = paramiko.SSHClient()
            filer_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            filer_client.connect(physical_filer, username="admin", password=admin_pass, sock=channel)

            # initial vserver-level clientmatch check (unchanged)
            vserver_cmd = f"export-policy rule show -vserver {vserver} -policyname * -fields clientmatch"
            vserver_out = run_check(filer_client, vserver_cmd, f_log=f_log, context=f"{vserver} - export-policy rule show")
            vserver_clients = parse_clientmatches_from_export_policy(vserver_out)
            extra_vserver = vserver_clients - global_clients

            if vserver_clients and not extra_vserver:
                # initial pass says "dedicated" -> reconfirm by is_vserver_really_dedicated
                dedicated_reconfirmed, reasons = is_vserver_really_dedicated(filer_client, vserver, global_clients, jump_client, admin_pass, f_log)
                if dedicated_reconfirmed:
                    log_append(f_log, f"==> RESULT: {vserver} | DEDICATED VSERVER {{reason: vserver-level checks passed}}", f_res)
                    collect_vserver_data(filer_client, vserver, f_log)
                    filer_client.close()
                    continue
                else:
                    log_append(f_log, f"==> RESULT: {vserver} | NOT A DEDICATED VSERVER {{reconfirm failed: {', '.join(reasons)}}}", f_res)
                    # fall through to per-volume logic
            else:
                log_append(f_log, f"==> RESULT: {vserver} | NOT A DEDICATED VSERVER {{reason: vserver-level export-policy had extra clients}}", f_res)

            # per-volume/policy logic
            for policy in sorted(input_policies):
                log_append(f_log, f"\nChecking input volume/policy: {policy}", f_res)
                ep_cmd = f"export-policy rule show -vserver {vserver} -policyname {policy} -fields clientmatch"
                ep_out = run_check(filer_client, ep_cmd, f_log=f_log, context=f"{vserver}:{policy} - export-policy rule show")

                found_clients = parse_clientmatches_from_export_policy(ep_out)
                extra = found_clients - global_clients
                vol_state = get_volume_state(filer_client, vserver, policy, f_log)

                # -----------------------------
                # if no clientmatches at policy level -> perform qtree-based decision using export-policy column
                # -----------------------------
                if not found_clients:
                    # === When no clientmatches found => Perform Qtree-based decision ===
                    qtree_cmd = f"qtree show -vserver {vserver} -volume {policy} -fields export-policy"
                    qtree_out = run_fetch(
                        filer_client,
                        qtree_cmd,
                        f_log=f_log,
                        context=f"{vserver}:{policy} - qtree show (not-found-clients logic)"
                    )

                    qtree_out_l = (qtree_out or "").lower().strip()

                    # === EXACT MESSAGE HANDLING ===
                    # if exact phrase present -> instruct manual check for volume name
                    if "there are no entries matching your query." in qtree_out_l or "there are no entries matching your query" in qtree_out_l:
                        status = "check manually - volume name"
                        log_append(
                            f_log,
                            f"==> RESULT: {vserver}:{policy} | {status}",
                            f_res
                        )
                        continue

                    if not qtree_out_l:
                        # No qtrees returned (empty output)
                        result = "Please check this manually."
                        log_append(
                            f_log,
                            f"==> RESULT: {vserver}:{policy} | {result} "
                            "{reason: No qtrees found during not-found-clients check}",
                            f_res
                        )
                        continue

                    # Parse qtrees and their export-policies
                    qtree_pairs = parse_qtrees_and_export_policies_from_qtree_show(qtree_out)
                    # Keep only non-empty rows (either qtree or export-policy)
                    non_empty_pairs = [pair for pair in qtree_pairs if pair[0] or pair[1]]

                    if not non_empty_pairs:
                        # All qtree names and export-policy values are blank/unusable
                        result = "Please check this manually."
                        log_append(
                            f_log,
                            f"==> RESULT: {vserver}:{policy} | {result} "
                            "{reason: Qtree list empty/blank in not-found-clients check}",
                            f_res
                        )
                        continue
                    else:
                        # Now check clientmatch for every qtree/export-policy pair
                        ok, reasons, external_clients = check_qtrees_against_global_using_export_policy(
                            filer_client, vserver, non_empty_pairs, global_clients, f_log
                        )

                        if ok:
                            result = "DEDICATED VOLUME"
                            reason = "All qtrees/export-policies contain only clients from input CSV"
                            log_append(
                                f_log,
                                f"==> RESULT: {vserver}:{policy} | {result} {{reason: {reason}}} | State: {vol_state}",
                                f_res
                            )
                        else:
                            result = "SHARED VOLUME"
                            reason = f"Qtrees/export-policies have external clients: {', '.join(sorted(external_clients))}"
                            log_append(
                                f_log,
                                f"==> RESULT: {vserver}:{policy} | {result} {{reason: {reason}}} | State: {vol_state}",
                                f_res
                            )
                        continue
                # -----------------------------
                # END qtree-based logic
                # -----------------------------
                elif extra:
                    # shared immediately at policy level
                    reason = f"extra client {', '.join(sorted(extra)[:1])}"
                    status = f"SHARED VOLUME"
                    log_append(f_log, f"==> RESULT: {vserver} | {policy} | {status} {{reason: {reason}}} | State: {vol_state}", f_res)
                    continue
                else:
                    # Candidate dedicated based on export-policy -> apply reconfirmation or special logic
                    p_low = policy.lower().strip()
                    if p_low.startswith("als_") or p_low.startswith("infra"):
                        # special logic applies (only after vserver decided NOT dedicated)
                        sp_status, sp_reasons = special_policy_volume_check(
                            filer_client, jump_client, admin_pass, vserver, policy, policy_to_clients, f_log
                        )
                        if sp_status.startswith("DEDICATED"):
                            status = "DEDICATED VOLUME"
                            reason_text = sp_reasons[0] if sp_reasons else "special logic passed"
                            collect_volume_data(filer_client, vserver, policy, f_log)
                            log_append(f_log, f"==> RESULT: {vserver} | {policy} | {status} {{reason: {reason_text}}} | State: {vol_state}", f_res)
                        else:
                            status = "SHARED VOLUME"
                            reason_text = sp_reasons[0] if sp_reasons else "special logic failed"
                            log_append(f_log, f"==> RESULT: {vserver} | {policy} | {status} {{reason: {reason_text}}} | State: {vol_state}", f_res)
                    else:
                        # regular reconfirmation flow
                        dedicated_reconfirmed, reasons = reconfirm_volume_dedicated(
                            filer_client, jump_client, admin_pass, vserver, policy, global_clients, f_log
                        )
                        if dedicated_reconfirmed:
                            status = "DEDICATED VOLUME"
                            log_append(f_log, f"==> RESULT: {vserver} | {policy} | {status} {{reason: reconfirmation passed}} | State: {vol_state}", f_res)
                            collect_volume_data(filer_client, vserver, policy, f_log)
                        else:
                            status = "SHARED VOLUME"
                            reason_text = ', '.join(reasons) if reasons else "reconfirm failed"
                            log_append(f_log, f"==> RESULT: {vserver} | {policy} | {status} {{reason: {reason_text}}} | State: {vol_state}", f_res)

            filer_client.close()

        except Exception as e:
            log_append(f_log, f"[ERROR] Failed nested SSH: {e}", f_res)

    jump_client.close()
    log_append(f_log, "\nDone.", f_res)
    f_log.close()
    f_res.close()

    print(f"\nConsolidated log saved to: {log_file}")
    print(f"Results-only log saved to: {result_file}")

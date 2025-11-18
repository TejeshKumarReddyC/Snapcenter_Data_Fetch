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
    "c860juu.int.thomsonreuters.com",
    "c860juu",
    "c240uih",
    "c240uih.int.thomsonreuters.com",
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

# Helpers to parse qtree output and extract qtree names (3rd column)
def parse_qtrees_from_qtree_show(output):
    """
    Robust qtree extractor for 'vol qtree show' output.
    """
    qtrees = []
    if not output:
        return qtrees

    def is_footer_line(s):
        return bool(re.search(r'\bentries?\b.*\bdisplayed\b', s)) or bool(re.match(r'^\d+\s+entries?\b', s))

    def is_timestamp_line(s):
        return bool(re.match(r'^\d{1,2}:\d{1,2}:\d{1,2}', s))

    valid_qtree_re = re.compile(r'^[A-Za-z0-9_.\-]+$')

    lines = [ln.rstrip() for ln in output.splitlines() if ln.strip()]

    header_idx = None
    for idx, ln in enumerate(lines):
        low = ln.lower()
        if 'vserver' in low and 'volume' in low and 'qtree' in low:
            header_idx = idx
            break

    data_start = (header_idx + 1) if header_idx is not None else 0

    for ln in lines[data_start:]:
        low = ln.lower().strip()

        if is_footer_line(low):
            continue
        if is_timestamp_line(low):
            continue
        if '&' in ln and not ':' in ln:
            pass

        if re.match(r'^[-=_\s]+$', ln):
            continue

        cols = re.split(r'\s{2,}', ln)
        if len(cols) < 3:
            cols = re.split(r'\s+', ln)
            if len(cols) < 3:
                continue

        raw_q = cols[2].strip().strip('"')
        if raw_q == '""' or raw_q == 'none':
            raw_q = ""

        if raw_q == "" or valid_qtree_re.match(raw_q):
            qtrees.append(raw_q)
        else:
            continue

    # dedupe preserving order
    seen = set()
    deduped = []
    for q in qtrees:
        if q not in seen:
            deduped.append(q)
            seen.add(q)

    return deduped

def check_qtrees_against_global(filer_client, vserver, qtree_list, global_clients, f_log):
    reasons = []
    for q in qtree_list:
        if not q:
            continue
        cmd = f"export-policy rule show -vserver {vserver} -policyname {q} -fields clientmatch"
        out = run_check(filer_client, cmd, f_log=f_log, context=f"{vserver}:{q} - export-policy (qtree)")
        clients = parse_clientmatches_from_export_policy(out)
        clients_l = {normalize_clientmatch(x) for x in clients if x}
        if not clients_l:
            continue
        extra = clients_l - global_clients
        if extra:
            reasons.append(f"qtree '{q}' has external clientmatch: {', '.join(sorted(extra))}")
            return False, reasons
    return True, []

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
        "Qtree relations": f"vol qtree show -vserver {vserver} -volume * -fields export-policy",
        "CIFS shares": f"cifs share show -vserver {vserver}",
        "LUNs": f"lun show -vserver {vserver}",
        "SnapMirror destinations": f"snapmirror list-destinations -source-path {vserver}:*",
    }
    for desc, cmd in commands.items():
        run_fetch(filer_client, cmd, f_log=f_log, context=f"{vserver} - {desc}")

def collect_volume_data(filer_client, vserver, volume, f_log):
    commands = {
        "CIFS shares": f"cifs share show -vserver {vserver}",
        "CIFS sessions": f"cifs session show -vserver {vserver}",
        "LUNs": f"lun show -vserver {vserver}",
        "Qtree relations": f"vol qtree show -vserver {vserver} -volume {volume} -fields export-policy",
        "SnapMirror destinations": f"snapmirror list-destinations -source-path {vserver}:{volume}",
        "Volume state": f"volume show -vserver {vserver} -volume {volume}",
    }
    for desc, cmd in commands.items():
        run_fetch(filer_client, cmd, f_log=f_log, context=f"{vserver}:{volume} - {desc}")

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
        src_qtrees = set(parse_qtrees_from_qtree_show(src_out))

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
            dst_qtrees = set(parse_qtrees_from_qtree_show(dst_out))
            dest_client.close()
        except Exception as e:
            reasons.append(f"failed to connect to destination physical filer {dest_physical} for {dst_v}: {e}")
            return False, reasons

        src_qtrees_norm = {q for q in src_qtrees if q}
        dst_qtrees_norm = {q for q in dst_qtrees if q}

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
        qtree_list = parse_qtrees_from_qtree_show(qtree_out)
        if not qtree_list or all(q == "" for q in qtree_list):
            pass
        else:
            non_empty_qtrees = [q for q in qtree_list if q]
            ok, q_reasons = check_qtrees_against_global(filer_client, vserver, non_empty_qtrees, global_clients, f_log)
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
        qtree_list = parse_qtrees_from_qtree_show(qtree_out)
        if all(q == "" for q in qtree_list):
            pass
        else:
            non_empty_qtrees = [q for q in qtree_list if q]
            ok, q_reasons = check_qtrees_against_global(filer_client, vserver, non_empty_qtrees, global_clients, f_log)
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
        q_cmd = f"qtree show -vserver {vserver} -volume {vol}"
        q_out = run_fetch(
            filer_client,
            q_cmd,
            f_log=f_log,
            context=f"{vserver}:{vol} - qtree show (special logic)"
        )

        qtrees = parse_qtrees_from_qtree_show(q_out)

        for q in qtrees:
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

    for q in target_qtrees:
        if not q:
            continue

        cmd = f"export-policy rule show -vserver {vserver} -policyname {q} -fields clientmatch"
        out = run_check(
            filer_client,
            cmd,
            f_log=f_log,
            context=f"{vserver}:{q} - export-policy (special check)"
        )

        clients = parse_clientmatches_from_export_policy(out)
        clients_l = {normalize_clientmatch(x) for x in clients if x}

        if not clients_l:
            continue  # empty clientmatch list = no violation

        extra = clients_l - set(allowed_clients)
        if extra:
            all_ok = False
            extra_clients_accum.update(extra)

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
    admin_pass = "zC0MgNT86e2Gcpl"

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
                # REPLACED BLOCK: if not found_clients -> qtree-based decision
                # -----------------------------
                if not found_clients:
                    # === When no clientmatches found => Perform Qtree-based decision ===
                    qtree_cmd = f"qtree show -vserver {vserver} -volume {policy}"
                    qtree_out = run_fetch(
                        filer_client,
                        qtree_cmd,
                        f_log=f_log,
                        context=f"{vserver}:{policy} - qtree show (not-found-clients logic)"
                    )

                    qtree_out_l = (qtree_out or "").lower().strip()

                    # === EXTRA CONDITION: exact "no entries" message -> specific text ===
                    if "there are no entries matching your query" in qtree_out_l:
                        status = "check manually - volume name"
                        log_append(
                            f_log,
                            f"==> RESULT: {vserver}:{policy} | {status}",
                            f_res
                        )
                        continue

                    if ("there are no entries matching your query." in qtree_out_l) or not qtree_out_l:
                        # No qtrees returned
                        result = "Please check this manually."
                        log_append(
                            f_log,
                            f"==> RESULT: {vserver}:{policy} | {result} "
                            "{reason: No qtrees found during not-found-clients check}",
                            f_res
                        )
                        continue

                    # Parse qtrees
                    qtree_list = parse_qtrees_from_qtree_show(qtree_out)
                    non_empty_qtrees = [q for q in qtree_list if q]

                    if not non_empty_qtrees:
                        # All qtree names are "" or unusable
                        result = "Please check this manually."
                        log_append(
                            f_log,
                            f"==> RESULT: {vserver}:{policy} | {result} "
                            "{reason: Qtree list empty/blank in not-found-clients check}",
                            f_res
                        )
                        continue
                    else:
                        # Now check clientmatch for every qtree
                        all_ok = True
                        external_clients = set()

                        for q in non_empty_qtrees:
                            ep_cmd_q = f"export-policy rule show -vserver {vserver} -policyname {q} -fields clientmatch"
                            ep_out_q = run_check(
                                filer_client,
                                ep_cmd_q,
                                f_log=f_log,
                                context=f"{vserver}:{q} - export-policy (not-found-clients)"
                            )

                            q_clients = parse_clientmatches_from_export_policy(ep_out_q)
                            q_clients_norm = {normalize_clientmatch(x) for x in q_clients if x}

                            extra_q = q_clients_norm - global_clients
                            if extra_q:
                                all_ok = False
                                external_clients.update(extra_q)

                        # Final classification
                        if all_ok:
                            result = "DEDICATED VOLUME"
                            reason = "All qtrees contain only clients from input CSV"
                        else:
                            result = "SHARED VOLUME"
                            reason = f"Qtrees have external clients: {', '.join(sorted(external_clients))}"

                        log_append(
                            f_log,
                            f"==> RESULT: {vserver}:{policy} | {result} {{reason: {reason}}}",
                            f_res
                        )
                        continue
                # -----------------------------
                # END REPLACED BLOCK
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

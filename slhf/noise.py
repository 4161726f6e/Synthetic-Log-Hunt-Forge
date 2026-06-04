from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from slhf.events import base_windows_event, syslog_event
from slhf.timing import TimingProfile, iso_z


WINDOWS_USERS = ["jdoe", "asmith", "bwilson", "svc_app", "svc_backup", "itadmin"]
PROCESSES     = ["chrome.exe", "outlook.exe", "teams.exe", "svchost.exe", "explorer.exe", "powershell.exe"]
PARENTS       = ["explorer.exe", "services.exe", "svchost.exe"]

# Processes whose canonical path is System32
_SYSTEM32_PROCS = frozenset({"svchost.exe", "explorer.exe", "powershell.exe"})


def generate_windows_noise(
    rng,
    hosts,
    start: datetime,
    end: datetime,
    level: str,
    noise_multiplier: float = 1.0,
) -> List[Dict[str, Any]]:
    mult = max(1, round({"low": 1, "medium": 3, "high": 8}[level] * noise_multiplier))
    timing = TimingProfile()
    events: List[Dict[str, Any]] = []

    total_seconds = int((end - start).total_seconds())
    # Pre-materialise host names once rather than re-accessing .name per event
    host_names = [h.name for h in hosts]

    for h in hosts:
        base_count = rng.randint(200, 400) * mult

        for _ in range(base_count):
            # FIX: sample once; only draw a replacement when the sample falls
            # outside business hours — avoiding the unconditional second draw.
            offset = rng.randint(0, total_seconds)
            t = start + timedelta(seconds=offset)
            m = timing.multiplier(t)
            if m < 1.0 and rng.random() > m:
                t = start + timedelta(seconds=rng.randint(0, total_seconds))

            ts = iso_z(t)
            e  = base_windows_event(ts, h.name)
            kind = rng.choice(("logon", "process", "service"))

            if kind == "logon":
                user     = rng.choice(WINDOWS_USERS)
                logon_id = hex(rng.randint(0x1000, 0xFFFFF))
                e["event_id"]   = 4624
                e["event_type"] = "logon_success"
                e["user"]["name"]     = user
                e["user"]["is_admin"] = user == "itadmin"
                e["logon"].update({
                    "logon_id":    logon_id,
                    "logon_type":  rng.choice((2, 3, 5, 7, 10)),
                    "source_ip":   f"10.0.{rng.randint(0,3)}.{rng.randint(1,254)}",
                    "source_host": rng.choice(host_names),   # FIX: use pre-built list
                })

            elif kind == "process":
                proc   = rng.choice(PROCESSES)
                parent = rng.choice(PARENTS)
                user   = rng.choice(WINDOWS_USERS)
                path = (
                    f"C:\\Windows\\System32\\{proc}"
                    if proc in _SYSTEM32_PROCS
                    else f"C:\\Program Files\\{proc}"
                )
                e["event_id"]   = 4688
                e["event_type"] = "process_creation"
                e["user"]["name"] = user
                e["process"].update({
                    "pid":          rng.randint(100, 9000),
                    "name":         proc,
                    "path":         path,
                    "command_line": "powershell.exe -NoProfile" if proc == "powershell.exe" else proc,
                })
                e["parent_process"].update({
                    "pid":  rng.randint(100, 9000),
                    "name": parent,
                    "path": f"C:\\Windows\\System32\\{parent}",
                })
                if rng.random() < 0.6:
                    e["logon"]["logon_id"] = hex(rng.randint(0x1000, 0xFFFFF))

            else:
                # Service install — deliberately rare
                e["event_id"]          = 7045
                e["event_type"]        = "service_install"
                e["user"]["name"]      = rng.choice(("SYSTEM", "itadmin", "svc_app"))
                e["metadata"]["severity"] = "informational"

            events.append(e)

    return events


def generate_syslog_noise(
    rng,
    linux_hosts,
    start: datetime,
    end: datetime,
    level: str,
    noise_multiplier: float = 1.0,
) -> List[Dict[str, Any]]:
    mult = max(1, round({"low": 1, "medium": 2, "high": 4}[level] * noise_multiplier))
    timing = TimingProfile()
    events: List[Dict[str, Any]] = []
    total_seconds = int((end - start).total_seconds())

    apps = ("sshd", "cron", "nginx", "sudo", "firewall", "apache")
    msgs = {
        "sshd":     ("Accepted password", "Failed password"),
        "cron":     ("Job started", "Job completed"),
        "nginx":    ("GET /index.html 200", "POST /login 302"),
        "sudo":     ("session opened", "user executed command"),
        "firewall": ("ALLOW TCP connection", "DENY inbound connection"),
        "apache":   ("GET / 200", "GET /health 200"),
    }

    for h in linux_hosts:
        count = rng.randint(80, 200) * mult
        for _ in range(count):
            # FIX: same single-sample-with-conditional-replacement pattern
            offset = rng.randint(0, total_seconds)
            t = start + timedelta(seconds=offset)
            m = timing.multiplier(t)
            if m < 1.0 and rng.random() > m:
                t = start + timedelta(seconds=rng.randint(0, total_seconds))

            app = rng.choice(apps)
            msg = rng.choice(msgs[app])
            events.append(syslog_event(iso_z(t), h.name, app, msg))

    return events

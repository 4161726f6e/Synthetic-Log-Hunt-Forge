from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class Host:
    name: str
    os: str
    role: str


# ---------------------------------------------------------------------------
# Name pools — varied but plausible corporate naming conventions
# ---------------------------------------------------------------------------
_DC_NAMES    = ["DC01", "DC02", "ADDC1", "ADDC2", "CORP-DC1", "CORP-DC2"]
_SRV_PREFIXES = ["SRV", "APP", "FILE", "PRINT", "MGMT", "WEB"]
_WS_PREFIXES  = ["WS", "DESK", "PC", "LAPTOP", "CLIENT", "WKST"]
_LINUX_PREFIXES = ["LINUX", "LX", "SVR", "WEB", "LOG", "DB"]


def generate_topology(rng) -> Dict[str, List[Host]]:
    """
    Build a varied but deterministic network topology seeded from *rng*.

    The topology is now actually seed-variable: host name prefixes, count of
    workstations (12–20), and count of Linux hosts (3–6) all vary by seed,
    giving each generated dataset a distinct-feeling environment.

    The number of DCs (always 2) and the general structure are fixed so the
    validator's assumptions hold regardless of seed.
    """
    hosts: List[Host] = []

    # Domain Controllers — always exactly 2, names vary by seed
    dc_names = rng.sample(_DC_NAMES, k=2)
    for name in dc_names:
        hosts.append(Host(name, "windows", "domain_controller"))

    # Windows servers — count fixed at 6, prefix varies
    srv_prefix = rng.choice(_SRV_PREFIXES)
    for i in range(1, 7):
        hosts.append(Host(f"{srv_prefix}{i:02d}", "windows", "server"))

    # Workstations — count varies 12–20 by seed
    ws_count  = rng.randint(12, 20)
    ws_prefix = rng.choice(_WS_PREFIXES)
    ws_base   = rng.randint(1000, 2000)
    for i in range(ws_count):
        hosts.append(Host(f"{ws_prefix}-{ws_base + i}", "windows", "workstation"))

    # Linux syslog hosts — count varies 3–6 by seed
    linux_count  = rng.randint(3, 6)
    linux_prefix = rng.choice(_LINUX_PREFIXES)
    for i in range(1, linux_count + 1):
        hosts.append(Host(f"{linux_prefix}{i:02d}", "linux", "linux_server"))

    groups = {
        "all":          hosts,
        "windows":      [h for h in hosts if h.os == "windows"],
        "linux":        [h for h in hosts if h.os == "linux"],
        "dcs":          [h for h in hosts if h.role == "domain_controller"],
        "workstations": [h for h in hosts if h.role == "workstation"],
        "servers":      [h for h in hosts if h.role == "server"],
    }
    return groups

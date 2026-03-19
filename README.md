<p align="center">
  <img src="docs/banner.svg" alt="Windows Red Teaming — MITRE ATT&CK Security Scanner" width="900"/>
</p>

<p align="center">
  <strong>Active scanning tool for authorized red team security assessments on Windows<br/>
  aligned with the MITRE ATT&CK Framework — 29 techniques across 7 tactics</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/license-MIT-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/techniques-29-ef4444?style=flat-square"/>
  <img src="https://img.shields.io/badge/tactics-7-f59e0b?style=flat-square"/>
  <img src="https://img.shields.io/badge/tests-85_passing-22c55e?style=flat-square"/>
  <img src="https://img.shields.io/badge/MITRE_ATT%26CK-13_tactics-dc2626?style=flat-square"/>
</p>

---

## Overview

**WindowsRedTeaming** is an open-source, Python-based active scanning tool designed for authorized red team security assessments on Windows systems. It evaluates security controls across Windows 10, 11, Server 2019, and Server 2022 by mapping checks directly to [MITRE ATT&CK](https://attack.mitre.org/) techniques.

The tool operates in two modes:

| Mode | Flag | Behavior |
|------|------|----------|
| **Check** *(default)* | -- | Passive, read-only security audit. Safe for production. |
| **Simulate** | `--simulate` | Active technique simulation with automatic cleanup. |

---

## Key Features

- **29 technique modules** across 7 ATT&CK tactics with full check/simulate/cleanup lifecycle
- **Module auto-discovery** -- drop a module in the right tactic folder, it's automatically picked up
- **Session abstraction** -- Local (subprocess), Remote WinRM (pypsrp), with SMB/WMI planned
- **ATT&CK Navigator export** -- generates JSON layer files for [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) visualization
- **Multi-format reports** -- HTML (dark theme), JSON, CSV
- **Evidence chain** -- every action logged with timestamps for audit trail
- **Scan profiles** -- quick, full, stealth, or custom YAML profiles
- **OS-aware execution** -- modules declare supported OS and auto-skip incompatible targets

---

## MITRE ATT&CK Coverage

```
+---------------------------+--------+--------------------------------------------------+
| Tactic                    | ID     | Techniques Implemented                           |
+---------------------------+--------+--------------------------------------------------+
| Reconnaissance            | TA0043 | T1595 Active Scanning                            |
+---------------------------+--------+--------------------------------------------------+
| Discovery                 | TA0007 | T1082 System Info, T1087 Account Discovery,      |
|                           |        | T1069 Permission Groups, T1046 Network Service,  |
|                           |        | T1083 File/Directory, T1057 Process Discovery,   |
|                           |        | T1049 Network Connections, T1016 Network Config  |
+---------------------------+--------+--------------------------------------------------+
| Credential Access         | TA0006 | T1003.001 LSASS Memory, T1003.002 SAM Database,  |
|                           |        | T1003.003 NTDS.dit, T1558.003 Kerberoasting,     |
|                           |        | T1552.001 Credentials in Files, T1110 Brute Force|
+---------------------------+--------+--------------------------------------------------+
| Privilege Escalation      | TA0004 | T1548.002 UAC Bypass, T1134 Token Manipulation,  |
|                           |        | T1574.001 DLL Search Order, T1574.002 DLL Sideload|
+---------------------------+--------+--------------------------------------------------+
| Execution                 | TA0002 | T1059.001 PowerShell, T1059.003 Command Shell,   |
|                           |        | T1047 WMI                                        |
+---------------------------+--------+--------------------------------------------------+
| Persistence               | TA0003 | T1053.005 Scheduled Tasks, T1547.001 Run Keys,   |
|                           |        | T1546.001 File Associations                      |
+---------------------------+--------+--------------------------------------------------+
| Defense Evasion           | TA0005 | T1562.001 Disable Security Tools,                |
|                           |        | T1562.002 Disable Event Logging,                 |
|                           |        | T1036 Masquerading, T1070.001 Clear Event Logs   |
+---------------------------+--------+--------------------------------------------------+
| Lateral Movement          | TA0008 | Planned (Phase 5)                                |
| Collection                | TA0009 | Planned (Phase 5)                                |
| Command & Control         | TA0011 | Planned (Phase 5)                                |
| Exfiltration              | TA0010 | Planned (Phase 5)                                |
| Impact                    | TA0040 | Planned (Phase 5)                                |
| Initial Access            | TA0001 | Planned                                          |
+---------------------------+--------+--------------------------------------------------+
```

---

## Quick Start

### Prerequisites

- Python 3.10+
- Windows target (local or remote via WinRM)

### Installation

```bash
git clone https://github.com/Krishcalin/Windows-Red-Teaming.git
cd Windows-Red-Teaming
pip install -r requirements.txt
```

### Usage

```bash
# Quick passive scan on local machine (safe, read-only)
python main.py scan --target localhost --profile quick

# Full scan against a remote target via WinRM
python main.py scan --target 192.168.1.10 --profile full

# Scan a specific tactic only
python main.py scan --target localhost --tactic discovery

# Scan a specific technique
python main.py scan --target localhost --technique T1082

# Full scan with active simulation (requires explicit flag)
python main.py scan --target 192.168.1.10 --profile full --simulate

# List all discovered modules
python main.py list-modules

# Generate report from a previous scan
python main.py report --input reports/scan_2026-03-16.json --format html
```

### Output Formats

```bash
# JSON report
python main.py scan --target localhost --format json --output report.json

# HTML report (dark theme)
python main.py scan --target localhost --format html --output report.html

# MITRE ATT&CK Navigator layer
python main.py scan --target localhost --format attack-layer --output layer.json
```

---

## Architecture

```
Windows-Red-Teaming/
|
|-- main.py                          # CLI entry point (click)
|-- core/
|   |-- engine.py                    # Scan orchestrator + module auto-discovery
|   |-- session.py                   # Local / WinRM session management
|   |-- models.py                    # Target, Finding, ModuleResult, ScanResult
|   |-- config.py                    # YAML config loader + profile merging
|   |-- logger.py                    # Structured logging + evidence chain
|   |-- reporter.py                  # HTML / JSON / CSV report generation
|   +-- mitre_mapper.py             # ATT&CK Navigator JSON layer export
|
|-- modules/
|   |-- base.py                      # BaseModule ABC (check/simulate/cleanup)
|   |-- reconnaissance/              # TA0043 -- 1 module
|   |-- discovery/                   # TA0007 -- 8 modules
|   |-- credential_access/           # TA0006 -- 6 modules
|   |-- privilege_escalation/        # TA0004 -- 4 modules
|   |-- execution/                   # TA0002 -- 3 modules
|   |-- persistence/                 # TA0003 -- 3 modules
|   |-- defense_evasion/             # TA0005 -- 4 modules
|   |-- lateral_movement/            # TA0008 -- planned
|   |-- collection/                  # TA0009 -- planned
|   |-- command_and_control/         # TA0011 -- planned
|   |-- exfiltration/                # TA0010 -- planned
|   +-- impact/                      # TA0040 -- planned
|
|-- config/
|   |-- techniques.yaml              # Enable/disable techniques
|   +-- profiles/
|       |-- quick.yaml               # Fast scan (8 key techniques)
|       |-- full.yaml                # All techniques
|       +-- stealth.yaml             # Minimal footprint (4 techniques)
|
|-- templates/
|   +-- report.html                  # Jinja2 dark-themed HTML report
|
+-- tests/                           # 85 pytest tests
```

### Module Contract

Every technique module inherits from `BaseModule` and implements:

```python
class MyTechniqueCheck(BaseModule):
    TECHNIQUE_ID   = "T1082"
    TECHNIQUE_NAME = "System Information Discovery"
    TACTIC         = "Discovery"
    SEVERITY       = Severity.MEDIUM
    SUPPORTED_OS   = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE      = True

    def check(self, session) -> ModuleResult:     # Passive, read-only
        ...
    def simulate(self, session) -> ModuleResult:  # Active (requires --simulate)
        ...
    def cleanup(self, session) -> None:           # Revert simulate changes
        ...
    def get_mitigations(self) -> list[str]:       # Remediation advice
        ...
```

---

## Scan Profiles

| Profile | Tactics | Techniques | Simulate | Use Case |
|---------|---------|------------|----------|----------|
| `quick` | Discovery, Credential Access, Defense Evasion | 8 high-value | No | Fast security posture check |
| `full` | All enabled | All enabled | No | Comprehensive passive audit |
| `stealth` | Discovery, Defense Evasion | 4 minimal | No | Low-footprint recon |

---

## Target OS Support

| Feature | Win 10 | Win 11 | Server 2019 | Server 2022 |
|---------|:------:|:------:|:-----------:|:-----------:|
| Local scan | Yes | Yes | Yes | Yes |
| WinRM remote | Yes | Yes | Yes | Yes |
| AMSI checks | Yes | Enhanced | Yes | Enhanced |
| Credential Guard | Optional | Default | Optional | Optional |
| NTDS.dit checks | -- | -- | Yes | Yes |
| AD/Domain checks | -- | -- | Yes | Yes |

---

## Safety & Authorization

> **WARNING:** This tool performs active security testing. Use ONLY on systems you are authorized to test. Unauthorized access to computer systems is illegal.

- Targets must be explicitly configured
- Default mode is **check-only** (passive, read-only)
- Active simulation requires the explicit `--simulate` CLI flag
- Authorization banner displayed before every scan
- Every action produces a timestamped audit log entry
- `cleanup()` is called automatically after every simulation
- Modules auto-skip if the target OS is not supported

---

## Development

### Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

### Adding a New Module

1. Create `modules/<tactic>/T{ID}_{name}.py`
2. Inherit from `BaseModule` and set all class attributes
3. Implement `check()`, `simulate()`, `cleanup()`, `get_mitigations()`
4. Add tests in `tests/test_modules/`
5. The engine auto-discovers it on next run

### Roadmap

- [x] **Phase 1** -- Foundation (engine, sessions, CLI, config, reporting)
- [x] **Phase 2** -- Discovery & Reconnaissance (9 modules)
- [x] **Phase 3** -- Credential Access & Privilege Escalation (10 modules)
- [x] **Phase 4** -- Execution, Persistence & Defense Evasion (10 modules)
- [ ] **Phase 5** -- Lateral Movement, C2 & Exfiltration
- [ ] **Phase 6** -- Reporting & ATT&CK Integration enhancements
- [ ] **Phase 7** -- Testing & CI/CD hardening

---

## License

[MIT License](LICENSE) -- Copyright (c) 2026 KRISH

---

<p align="center">
  <sub>Built for authorized security testing and red team assessments only.</sub>
</p>

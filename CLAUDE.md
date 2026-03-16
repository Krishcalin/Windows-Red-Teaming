# CLAUDE.md — Windows Red Teaming Tool

## Project Overview

An open-source Python-based active scanning tool for red team security testing on Windows systems,
aligned with the MITRE ATT&CK Framework. The tool tests security controls across Windows 10, 11,
Server 2019, and Server 2022.

**Repository**: https://github.com/Krishcalin/Windows-Red-Teaming
**License**: MIT
**Python**: 3.10+

---

## Architecture

### Directory Structure

```
Windows-Red-Teaming/
├── config/                        # Configuration files
│   ├── settings.yaml              # Global config (targets, credentials, scope)
│   ├── techniques.yaml            # Enable/disable specific ATT&CK techniques
│   └── profiles/                  # Scan profiles (quick, full, stealth)
│       ├── quick.yaml
│       ├── full.yaml
│       └── stealth.yaml
├── core/                          # Core engine components
│   ├── __init__.py
│   ├── engine.py                  # Main orchestrator — loads modules, runs scans
│   ├── session.py                 # Target session management (WinRM/SMB/WMI/local)
│   ├── logger.py                  # Structured logging + evidence chain
│   ├── reporter.py                # Report generation (HTML/JSON/CSV)
│   ├── mitre_mapper.py            # Maps results → ATT&CK Navigator JSON layers
│   └── models.py                  # Data models (ModuleResult, Finding, Target)
├── modules/                       # One package per MITRE ATT&CK tactic
│   ├── __init__.py
│   ├── base.py                    # Abstract BaseModule class (all modules inherit)
│   ├── reconnaissance/            # TA0043
│   ├── initial_access/            # TA0001
│   ├── execution/                 # TA0002
│   ├── persistence/               # TA0003
│   ├── privilege_escalation/      # TA0004
│   ├── defense_evasion/           # TA0005
│   ├── credential_access/         # TA0006
│   ├── discovery/                 # TA0007
│   ├── lateral_movement/          # TA0008
│   ├── collection/                # TA0009
│   ├── command_and_control/       # TA0011
│   ├── exfiltration/              # TA0010
│   └── impact/                    # TA0040
├── templates/                     # Jinja2 report templates
│   └── report.html
├── reports/                       # Generated report output (gitignored)
├── evidence/                      # Collected artifacts (gitignored)
├── tests/                         # pytest tests
│   ├── conftest.py
│   ├── test_engine.py
│   ├── test_session.py
│   └── test_modules/
├── main.py                        # CLI entry point (click-based)
├── pyproject.toml                 # Project metadata + dependencies
├── requirements.txt               # Pinned dependencies
├── CLAUDE.md                      # This file
└── README.md
```

### Core Design Principles

1. **Module-per-technique** — each ATT&CK technique is a self-contained Python module
2. **Safe by default** — `check()` mode is passive/read-only; `simulate()` requires explicit `--simulate` flag
3. **OS-aware** — modules declare `SUPPORTED_OS` and auto-skip unsupported targets
4. **Auto-discovery** — engine discovers modules by scanning `modules/` packages at runtime
5. **Evidence chain** — every action logged with timestamp, target, technique ID, result

### BaseModule Contract

All technique modules inherit from `modules/base.py:BaseModule` and must implement:

- `check(session) -> ModuleResult` — passive detection (read-only, no system changes)
- `simulate(session) -> ModuleResult` — active simulation (requires --simulate flag)
- `cleanup(session)` — revert any changes made during simulate
- `get_mitigations() -> list[str]` — recommended remediations

Required class attributes: `TECHNIQUE_ID`, `TECHNIQUE_NAME`, `TACTIC`, `SEVERITY`,
`SUPPORTED_OS`, `REQUIRES_ADMIN`, `SAFE_MODE`.

### Session Management

- **Local**: Direct Windows API calls via `ctypes`/`pywin32`/`subprocess`
- **Remote WinRM**: Via `pypsrp` — PowerShell remoting
- **Remote SMB**: Via `impacket` — file shares, named pipes
- **Remote WMI**: Via `impacket` — WMI queries and execution

---

## MITRE ATT&CK Tactic Coverage

| Tactic | ID | Module Package | Priority Techniques |
|--------|----|----------------|---------------------|
| Reconnaissance | TA0043 | `modules/reconnaissance/` | T1595, T1592 |
| Initial Access | TA0001 | `modules/initial_access/` | T1078, T1190 |
| Execution | TA0002 | `modules/execution/` | T1059, T1047, T1053, T1106 |
| Persistence | TA0003 | `modules/persistence/` | T1547, T1136, T1546, T1053 |
| Privilege Escalation | TA0004 | `modules/privilege_escalation/` | T1134, T1055, T1548, T1574 |
| Defense Evasion | TA0005 | `modules/defense_evasion/` | T1562, T1036, T1070, T1027 |
| Credential Access | TA0006 | `modules/credential_access/` | T1003, T1558, T1110, T1552 |
| Discovery | TA0007 | `modules/discovery/` | T1087, T1082, T1046, T1083 |
| Lateral Movement | TA0008 | `modules/lateral_movement/` | T1021, T1550, T1570 |
| Collection | TA0009 | `modules/collection/` | T1113, T1560, T1074 |
| Command & Control | TA0011 | `modules/command_and_control/` | T1071, T1573, T1090 |
| Exfiltration | TA0010 | `modules/exfiltration/` | T1048, T1041 |
| Impact | TA0040 | `modules/impact/` | T1489, T1486, T1529 |

---

## Target OS Compatibility

| Feature | Win 10 | Win 11 | Server 2019 | Server 2022 |
|---------|--------|--------|-------------|-------------|
| WinRM | Yes | Yes | Yes | Yes |
| WMI | Yes | Yes | Yes | Yes |
| PowerShell 5.1 | Yes | Yes | Yes | Yes |
| AMSI | Yes | Enhanced | Yes | Enhanced |
| Credential Guard | Optional | Default | Optional | Optional |
| WDAC/AppLocker | Enterprise | Enterprise | Yes | Yes |
| AD-specific tests | N/A | N/A | Yes | Yes |

---

## Development Phases

### Phase 1 — Foundation (Current)
- [ ] Project scaffolding: `pyproject.toml`, `requirements.txt`, `.gitignore`
- [ ] Core engine (`core/engine.py`) with module auto-discovery
- [ ] Session manager (`core/session.py`) — local + WinRM
- [ ] BaseModule abstract class (`modules/base.py`)
- [ ] Data models (`core/models.py`) — ModuleResult, Finding, Target
- [ ] Structured logger (`core/logger.py`)
- [ ] CLI entry point (`main.py`) with click
- [ ] Config system (YAML loading + profiles)

### Phase 2 — Discovery & Reconnaissance Modules
- [ ] T1082 System Information Discovery
- [ ] T1087 Account Discovery (local + domain)
- [ ] T1069 Permission Groups Discovery
- [ ] T1046 Network Service Discovery
- [ ] T1083 File and Directory Discovery
- [ ] T1057 Process Discovery
- [ ] T1049 System Network Connections Discovery
- [ ] T1016 System Network Configuration Discovery
- [ ] T1595 Active Scanning

### Phase 3 — Credential Access & Privilege Escalation
- [ ] T1003.001 LSASS Memory protection check
- [ ] T1003.002 SAM Database access check
- [ ] T1003.003 NTDS.dit access check
- [ ] T1558.003 Kerberoasting vulnerability
- [ ] T1552.001 Credentials in Files
- [ ] T1110 Brute Force policy check
- [ ] T1548.002 UAC Bypass checks
- [ ] T1134 Access Token Manipulation
- [ ] T1574.001 DLL Search Order Hijacking
- [ ] T1574.002 DLL Side-Loading

### Phase 4 — Execution, Persistence & Defense Evasion
- [ ] T1059.001 PowerShell policy audit
- [ ] T1059.003 Windows Command Shell restrictions
- [ ] T1047 WMI access controls
- [ ] T1053.005 Scheduled Task audit
- [ ] T1547.001 Registry Run Keys audit
- [ ] T1546.001 Change Default File Association
- [ ] T1562.001 Disable/Modify Security Tools (AV/EDR status)
- [ ] T1562.002 Disable Windows Event Logging
- [ ] T1036 Masquerading detection
- [ ] T1070.001 Clear Windows Event Logs capability

### Phase 5 — Lateral Movement, C2 & Exfiltration
- [ ] T1021.001 RDP configuration audit
- [ ] T1021.002 SMB/Admin Shares audit
- [ ] T1021.006 WinRM configuration audit
- [ ] T1550.002 Pass the Hash feasibility
- [ ] T1071.001 Web Protocol C2 (outbound HTTP/S checks)
- [ ] T1048 Exfiltration channel detection
- [ ] T1041 C2 channel exfiltration check

### Phase 6 — Reporting & ATT&CK Integration
- [ ] ATT&CK Navigator JSON layer export
- [ ] HTML report with executive summary
- [ ] JSON/CSV machine-readable output
- [ ] Per-technique detail pages with mitigations
- [ ] CIS Benchmark / NIST 800-53 mapping

### Phase 7 — Testing & Hardening
- [ ] Unit tests per module
- [ ] Integration tests against lab VMs (Win10/11/2019/2022)
- [ ] Safety controls validation (dry-run, rollback)
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] User documentation

---

## Key Dependencies

```
impacket>=0.11.0          # SMB, WMI, Kerberos, NTLM protocols
pypsrp>=0.8.0             # WinRM / PowerShell remoting
mitreattack-python        # Official MITRE ATT&CK STIX data
click>=8.0                # CLI framework
pyyaml>=6.0               # YAML config parsing
jinja2>=3.1               # Report templating
rich>=13.0                # Terminal UI, tables, progress bars
structlog>=23.0           # Structured logging
cryptography>=41.0        # Encryption utilities
```

For local Windows execution only: `pywin32`

---

## Coding Conventions

- Python 3.10+ (use `match/case`, `X | Y` union types where appropriate)
- Type hints on all public functions
- Module file naming: `T{id}_{short_name}.py` (e.g., `T1059_command_scripting.py`)
- One class per module file, class name matches technique (e.g., `CommandScriptingCheck`)
- Use `structlog` for all logging — never bare `print()`
- Tests mirror source layout under `tests/test_modules/`
- All config via YAML — no hardcoded values

---

## Safety & Authorization

- Targets must be explicitly whitelisted in `config/settings.yaml`
- Default mode is **check-only** (passive, read-only)
- Active simulation requires `--simulate` CLI flag
- Authorization banner displayed before any scan
- Every action produces an audit log entry
- `cleanup()` must be implemented for every simulate-capable module
- OS guard: modules auto-skip if target OS not in `SUPPORTED_OS`

---

## Running the Tool

```bash
# Quick passive scan (check-only, safe)
python main.py scan --target 192.168.1.10 --profile quick

# Full scan with active simulation
python main.py scan --target 192.168.1.10 --profile full --simulate

# Scan specific tactic only
python main.py scan --target 192.168.1.10 --tactic discovery

# Scan specific technique
python main.py scan --target 192.168.1.10 --technique T1082

# Local machine scan
python main.py scan --target localhost

# Generate report from previous scan
python main.py report --input reports/scan_2026-03-16.json --format html
```

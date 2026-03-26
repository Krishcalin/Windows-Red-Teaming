# CLAUDE.md — Windows Red Teaming Tool

## Project Overview

An open-source Python-based active scanning tool for authorized red team security testing on
Windows systems, aligned with the MITRE ATT&CK Framework. The tool uses a dual-mode architecture:
29 Python modules for passive security auditing and active simulation, plus 202 YAML-based
atomic tests (inspired by Atomic Red Team) for technique execution across all 13 ATT&CK tactics.

**Repository**: https://github.com/Krishcalin/Windows-Red-Teaming
**License**: MIT
**Python**: 3.10+
**Status**: Phases 1-5 complete (29 Python modules + 202 YAML atomic tests)

---

## Architecture

### Directory Structure

```
Windows-Red-Teaming/
├── main.py                        # CLI entry point (Click: scan, list-modules, run-atomic, report)
├── core/                          # Core engine components
│   ├── __init__.py                # Package init (__version__ = "1.0.0")
│   ├── engine.py                  # ScanEngine — discovers Python modules + YAML atomics, runs scans
│   ├── session.py                 # BaseSession ABC, LocalSession (subprocess), WinRMSession (pypsrp)
│   ├── models.py                  # Target, Finding, ModuleResult, ScanResult, Severity, OSType, ModuleStatus
│   ├── atomic_models.py           # AtomicTechnique, AtomicTest, InputArgument, Dependency, Executor
│   ├── atomic_runner.py           # AtomicRunner — loads atomics/ YAMLs, checks deps, executes, cleans up
│   ├── config.py                  # ScanConfig, load_settings, load_techniques, load_profile, build_config
│   ├── logger.py                  # structlog setup + EvidenceLogger audit chain
│   ├── reporter.py                # Reporter — HTML (Jinja2) / JSON / CSV report generation
│   └── mitre_mapper.py            # MitreMapper — ATT&CK Navigator v4.5 JSON layer export
├── modules/                       # Python technique modules (BaseModule subclasses)
│   ├── __init__.py
│   ├── base.py                    # BaseModule ABC (check/simulate/cleanup/get_mitigations)
│   ├── reconnaissance/            # TA0043 — 1 module  (T1595)
│   ├── discovery/                 # TA0007 — 8 modules (T1082, T1087, T1069, T1046, T1083, T1057, T1049, T1016)
│   ├── execution/                 # TA0002 — 3 modules (T1059.001, T1059.003, T1047)
│   ├── persistence/               # TA0003 — 3 modules (T1053.005, T1547.001, T1546.001)
│   ├── privilege_escalation/      # TA0004 — 4 modules (T1548.002, T1134, T1574.001, T1574.002)
│   ├── credential_access/         # TA0006 — 6 modules (T1003.001/.002/.003, T1558.003, T1552.001, T1110)
│   ├── defense_evasion/           # TA0005 — 4 modules (T1562.001/.002, T1036, T1070.001)
│   ├── lateral_movement/          # TA0008 — empty (covered by YAML atomics)
│   ├── collection/                # TA0009 — empty (covered by YAML atomics)
│   ├── command_and_control/       # TA0011 — empty (covered by YAML atomics)
│   ├── exfiltration/              # TA0010 — empty (covered by YAML atomics)
│   └── impact/                    # TA0040 — empty (covered by YAML atomics)
├── atomics/                       # YAML-based atomic tests (ART-style, 61 techniques, 202 tests)
│   ├── T1082/T1082.yaml           # System Info Discovery (10 tests)
│   ├── T1087.001/T1087.001.yaml   # Local Account Discovery (4 tests)
│   ├── T1087.002/T1087.002.yaml   # Domain Account Discovery (5 tests)
│   ├── T1059.001/T1059.001.yaml   # PowerShell (7 tests)
│   ├── T1562.001/T1562.001.yaml   # Disable Security Tools (6 tests)
│   ├── T1003.001/T1003.001.yaml   # LSASS Memory (4 tests)
│   ├── T1105/T1105.yaml           # Ingress Tool Transfer (5 tests)
│   ├── T1021.001/T1021.001.yaml   # RDP (4 tests)
│   ├── T1490/T1490.yaml           # Inhibit System Recovery (4 tests)
│   └── ... (61 technique directories total)
├── config/                        # Configuration files
│   ├── settings.example.yaml      # Template: targets, credentials, output, logging, safety
│   ├── techniques.yaml            # Enable/disable specific ATT&CK techniques (99 entries)
│   └── profiles/                  # Scan profiles
│       ├── quick.yaml             # 8 high-value techniques
│       ├── full.yaml              # All discovered modules
│       └── stealth.yaml           # 4 minimal-footprint checks
├── templates/
│   └── report.html                # Jinja2 dark-themed HTML report template
├── tests/                         # pytest test suite (122 tests)
│   ├── conftest.py                # Shared fixtures (mock_session, sample_target, sample_finding)
│   ├── test_engine.py             # ScanEngine module discovery + authorization banner
│   ├── test_models.py             # Finding, ModuleResult, ScanResult dataclass tests
│   ├── test_session.py            # Session creation, connect/disconnect, command result
│   ├── test_atomic_models.py      # InputArgument, Dependency, Executor, AtomicTest, AtomicTechnique (17 tests)
│   ├── test_atomic_runner.py      # AtomicRunner discovery, filters, execution, deps, cleanup (20 tests)
│   └── test_modules/              # Per-module tests
│       ├── test_discovery.py
│       ├── test_credential_access.py
│       ├── test_privilege_escalation.py
│       └── test_phase4.py
├── reports/                       # Generated report output (gitignored)
├── evidence/                      # Audit trail storage (gitignored)
├── docs/                          # Banner SVG
├── pyproject.toml                 # Project metadata + dependencies
├── requirements.txt               # Pinned dependencies
└── README.md
```

### Core Design Principles

1. **Dual-mode architecture** — Python modules for deep audit logic; YAML atomics for broad technique coverage
2. **Safe by default** — `check()` mode is passive/read-only; `simulate()` and YAML atomics require explicit flags
3. **OS-aware** — Python modules declare `SUPPORTED_OS` and auto-skip unsupported targets
4. **Auto-discovery** — engine discovers Python modules from `modules/` and YAML tests from `atomics/` at runtime
5. **Evidence chain** — every action logged with timestamp, target, technique ID, result, and findings count
6. **Cleanup guarantee** — both Python `cleanup()` and YAML `cleanup_command` run automatically after simulation

### BaseModule Contract

All Python technique modules inherit from `modules/base.py:BaseModule` and must implement:

- `check(session) -> ModuleResult` — passive detection (read-only, no system changes)
- `simulate(session) -> ModuleResult` — active simulation (requires `--simulate` flag)
- `cleanup(session)` — revert any changes made during simulate
- `get_mitigations() -> list[str]` — recommended remediations

Required class attributes: `TECHNIQUE_ID`, `TECHNIQUE_NAME`, `TACTIC`, `SEVERITY`,
`SUPPORTED_OS`, `REQUIRES_ADMIN`, `SAFE_MODE`.

Helper methods: `create_result()`, `add_finding()`, `supports_os()`, `skip_result()`, `error_result()`.

### Atomic Test Schema

YAML atomic test files (`atomics/<ID>/<ID>.yaml`) follow this schema:

```yaml
attack_technique: "T1082"           # MITRE ATT&CK technique ID (required)
display_name: "Technique Name"      # Human-readable name (required)
tactic: "Discovery"                 # Primary ATT&CK tactic (optional, auto-resolved)
atomic_tests:                       # List of tests (required, min 1)
  - name: "Test Name"              # Short descriptive name (required)
    auto_generated_guid: "uuid"    # Unique test identifier (optional)
    description: "..."             # What the test does (required)
    supported_platforms: [windows]  # Target platforms (required)
    input_arguments:               # Parameterized inputs (optional)
      arg_name:
        description: "..."
        type: string|path|url|integer|float
        default: "value"
    dependencies:                  # Prerequisites (optional)
      - description: "..."
        prereq_command: "exit 0 if met"
        get_prereq_command: "install command"
    dependency_executor_name: powershell  # Executor for prereq checks (optional)
    executor:                      # How to run the test (required)
      name: powershell|command_prompt|manual
      command: "..."               # Command with #{arg} substitution
      cleanup_command: "..."       # Cleanup with #{arg} substitution (optional)
      elevation_required: false    # Needs admin? (optional, default false)
```

### Session Management

- **LocalSession**: Uses `subprocess.run()` for `cmd.exe` and `powershell.exe` execution
- **WinRMSession**: Uses `pypsrp.Client` for remote PowerShell and command execution
- **SMB/WMI**: Planned (connection methods defined but not yet implemented)

Session interface methods: `connect()`, `disconnect()`, `run_cmd()`, `run_powershell()`,
`read_registry()`, `file_exists()`, `read_file()`, `detect_os()`.

### Scan Engine Flow

1. **Discover** Python modules from `modules/` package tree + YAML atomics from `atomics/`
2. **Apply filters** by tactic, technique ID, enabled/disabled sets from config/profile
3. **Create session** (LocalSession or WinRMSession based on target)
4. **Detect OS** if not pre-set
5. **Phase 1**: Run Python module `check()` on each matching module
6. **Phase 2** (if `--simulate`): Run `simulate()` + `cleanup()` on Python modules
7. **Phase 2** (if `--simulate`): Run YAML atomic tests for techniques not covered by Python modules
8. **Generate reports** (HTML, JSON, CSV, ATT&CK Navigator layer)
9. **Save evidence chain**

---

## MITRE ATT&CK Tactic Coverage

### Python Modules (29 total, 7 tactics)

| Tactic | ID | Modules | Techniques |
|--------|----|:-------:|------------|
| Reconnaissance | TA0043 | 1 | T1595 |
| Discovery | TA0007 | 8 | T1082, T1087, T1069, T1046, T1083, T1057, T1049, T1016 |
| Execution | TA0002 | 3 | T1059.001, T1059.003, T1047 |
| Persistence | TA0003 | 3 | T1053.005, T1547.001, T1546.001 |
| Privilege Escalation | TA0004 | 4 | T1548.002, T1134, T1574.001, T1574.002 |
| Credential Access | TA0006 | 6 | T1003.001, T1003.002, T1003.003, T1558.003, T1552.001, T1110 |
| Defense Evasion | TA0005 | 4 | T1562.001, T1562.002, T1036, T1070.001 |

### YAML Atomic Tests (202 tests, 61 techniques, 11 tactics)

| Tactic | Techniques | Tests | Top technique by test count |
|--------|:----------:|:-----:|---------------------------|
| Discovery | 19 | 73 | T1082 (10), T1059.001 (7), T1087.002 (5) |
| Execution | 6 | 24 | T1059.001 (7), T1047 (4), T1053.005 (4) |
| Persistence | 7 | 20 | T1547.001 (4), T1546.008 (3), T1543.003 (3) |
| Defense Evasion | 4 | 17 | T1562.001 (6), T1562.002 (4), T1112 (4) |
| Credential Access | 6 | 20 | T1003.001 (4), T1552.001 (4), T1558.003 (3) |
| Privilege Escalation | 1 | 4 | T1548.002 (4) |
| Lateral Movement | 4 | 12 | T1021.001 (4), T1021.002 (3), T1021.006 (3) |
| Collection | 5 | 8 | T1113 (2), T1560.001 (2), T1219 (2) |
| Command & Control | 3 | 9 | T1105 (5), T1071.001 (2), T1219 (2) |
| Exfiltration | 1 | 3 | T1048.003 (3) |
| Impact | 5 | 12 | T1490 (4), T1489 (2), T1529 (2) |

---

## Target OS Compatibility

| Feature | Win 10 | Win 11 | Server 2019 | Server 2022 |
|---------|:------:|:------:|:-----------:|:-----------:|
| Local scan | Yes | Yes | Yes | Yes |
| WinRM remote | Yes | Yes | Yes | Yes |
| PowerShell 5.1 | Yes | Yes | Yes | Yes |
| AMSI | Yes | Enhanced | Yes | Enhanced |
| Credential Guard | Optional | Default | Optional | Optional |
| WDAC/AppLocker | Enterprise | Enterprise | Yes | Yes |
| AD-specific tests | N/A | N/A | Yes | Yes |

---

## Development Phases

### Phase 1 — Foundation (COMPLETE)
- [x] Project scaffolding: `pyproject.toml`, `requirements.txt`, `.gitignore`
- [x] Core engine (`core/engine.py`) with module auto-discovery
- [x] Session manager (`core/session.py`) — LocalSession + WinRMSession
- [x] BaseModule abstract class (`modules/base.py`)
- [x] Data models (`core/models.py`) — ModuleResult, Finding, Target, Severity, OSType
- [x] Structured logger (`core/logger.py`) + EvidenceLogger
- [x] CLI entry point (`main.py`) with Click
- [x] Config system (`core/config.py`) — YAML loading + profiles + technique filters

### Phase 2 — Discovery & Reconnaissance (COMPLETE)
- [x] T1082 System Information Discovery
- [x] T1087 Account Discovery (local + domain)
- [x] T1069 Permission Groups Discovery
- [x] T1046 Network Service Discovery
- [x] T1083 File and Directory Discovery
- [x] T1057 Process Discovery
- [x] T1049 System Network Connections Discovery
- [x] T1016 System Network Configuration Discovery
- [x] T1595 Active Scanning

### Phase 3 — Credential Access & Privilege Escalation (COMPLETE)
- [x] T1003.001 LSASS Memory protection check
- [x] T1003.002 SAM Database access check
- [x] T1003.003 NTDS.dit access check
- [x] T1558.003 Kerberoasting vulnerability
- [x] T1552.001 Credentials in Files
- [x] T1110 Brute Force policy check
- [x] T1548.002 UAC Bypass checks
- [x] T1134 Access Token Manipulation
- [x] T1574.001 DLL Search Order Hijacking
- [x] T1574.002 DLL Side-Loading

### Phase 4 — Execution, Persistence & Defense Evasion (COMPLETE)
- [x] T1059.001 PowerShell policy audit
- [x] T1059.003 Windows Command Shell restrictions
- [x] T1047 WMI access controls
- [x] T1053.005 Scheduled Task audit
- [x] T1547.001 Registry Run Keys audit
- [x] T1546.001 Change Default File Association
- [x] T1562.001 Disable/Modify Security Tools (AV/EDR status)
- [x] T1562.002 Disable Windows Event Logging
- [x] T1036 Masquerading detection
- [x] T1070.001 Clear Windows Event Logs capability

### Phase 5 — Atomic Test Library (COMPLETE)
- [x] Atomic data models (`core/atomic_models.py`) — AtomicTechnique, AtomicTest, InputArgument, Dependency, Executor
- [x] Atomic test runner (`core/atomic_runner.py`) — YAML loading, dependency checking, execution, cleanup
- [x] Engine integration — ScanEngine discovers + runs YAML atomics alongside Python modules
- [x] CLI enhancements — `list-modules --source [all|python|atomic]`, `run-atomic --technique <ID>`
- [x] 61 techniques, 202 atomic tests across all 13 MITRE ATT&CK tactics
- [x] Lateral Movement: T1021.001 RDP, T1021.002 SMB, T1021.006 WinRM, T1550.002 PtH
- [x] Collection: T1113 Screen Capture, T1560.001 Archive, T1074.001 Staging, T1115 Clipboard
- [x] Command & Control: T1105 Ingress Transfer (5 methods), T1071.001 Web Protocols, T1219 RAT Detection
- [x] Exfiltration: T1048.003 DNS/ICMP/SMB exfiltration simulation
- [x] Impact: T1489 Service Stop, T1490 Inhibit Recovery, T1529 Shutdown, T1485 Destruction, T1531 Account Removal
- [x] 37 new pytest tests (test_atomic_models.py + test_atomic_runner.py)

### Phase 6 — Reporting & ATT&CK Integration
- [x] ATT&CK Navigator JSON layer export (`core/mitre_mapper.py`)
- [x] HTML report with executive summary (`core/reporter.py` + `templates/report.html`)
- [x] JSON/CSV machine-readable output
- [ ] Per-technique detail pages with mitigations
- [ ] CIS Benchmark / NIST 800-53 mapping

### Phase 7 — Testing & Hardening
- [x] Unit tests (122 passing — 85 module + 37 atomic framework)
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
pyyaml>=6.0               # YAML config + atomic test parsing
jinja2>=3.1               # Report templating
rich>=13.0                # Terminal UI, tables, progress bars
structlog>=23.0           # Structured logging
cryptography>=41.0        # Encryption utilities
```

Optional (local Windows execution): `pywin32>=306`
Optional (testing): `pytest>=7.0`, `pytest-cov>=4.0`, `pytest-mock>=3.0`

---

## Coding Conventions

- Python 3.10+ (use `match/case`, `X | Y` union types where appropriate)
- Type hints on all public functions
- Python module file naming: `T{id}_{short_name}.py` (e.g., `T1059_command_scripting.py`)
- Atomic test file naming: `atomics/T{id}/T{id}.yaml` (e.g., `atomics/T1082/T1082.yaml`)
- One class per module file, class name matches technique (e.g., `CommandScriptingCheck`)
- Use `structlog` for all logging — never bare `print()`
- Tests mirror source layout under `tests/test_modules/`
- All config via YAML — no hardcoded values

---

## Safety & Authorization

- Targets must be explicitly whitelisted in `config/settings.yaml`
- Default mode is **check-only** (passive, read-only)
- Active simulation requires `--simulate` CLI flag
- YAML atomic tests only run in simulate mode or via `run-atomic` command
- Authorization banner displayed and confirmed before any scan
- Every action produces an audit log entry in `evidence/`
- `cleanup()` and `cleanup_command` run automatically after every simulation
- OS guard: Python modules auto-skip if target OS not in `SUPPORTED_OS`

---

## Running the Tool

```bash
# ── Passive scanning (check mode) ──────────────────────────────
python main.py scan --target localhost --profile quick
python main.py scan --target 192.168.1.10 --profile full
python main.py scan --target localhost --tactic discovery
python main.py scan --target localhost --technique T1082

# ── Active simulation (Python modules + YAML atomic tests) ─────
python main.py scan --target 192.168.1.10 --profile full --simulate

# ── Run YAML atomic tests for a single technique ────────────────
python main.py run-atomic --target localhost --technique T1082
python main.py run-atomic --target localhost --technique T1059.001 --format json -o report

# ── Module discovery ────────────────────────────────────────────
python main.py list-modules                    # All (Python + atomic)
python main.py list-modules --source python    # Python modules only
python main.py list-modules --source atomic    # YAML atomic tests only

# ── Report generation from previous scan ────────────────────────
python main.py report --input reports/scan_20260326.json --format html
python main.py report --input reports/scan_20260326.json --format attack-layer
```

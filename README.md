<p align="center">
  <img src="docs/banner.svg" alt="Windows Red Teaming — MITRE ATT&CK Security Scanner" width="900"/>
</p>

<p align="center">
  <strong>Python-based Windows red team scanner with dual-mode architecture:<br/>
  29 Python audit modules + 202 Atomic Red Team-style YAML tests across 13 MITRE ATT&CK tactics</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/license-MIT-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/techniques-90-ef4444?style=flat-square"/>
  <img src="https://img.shields.io/badge/atomic_tests-202-dc2626?style=flat-square"/>
  <img src="https://img.shields.io/badge/tactics-13-f59e0b?style=flat-square"/>
  <img src="https://img.shields.io/badge/tests-122_passing-22c55e?style=flat-square"/>
</p>

---

## Overview

**Windows Red Teaming** is an open-source, authorized red team security assessment tool for Windows 10, 11, Server 2019, and Server 2022. It maps every check to [MITRE ATT&CK](https://attack.mitre.org/) techniques and combines two complementary scanning approaches:

| Layer | Source | Count | Purpose |
|-------|--------|-------|---------|
| **Python modules** | `modules/` | 29 modules across 7 tactics | Passive security posture audit (`check`) + active simulation (`simulate`) with cleanup |
| **YAML atomic tests** | `atomics/` | 202 tests across 61 techniques | Atomic Red Team-style technique execution with input arguments, dependencies, and cleanup |

The tool operates in three modes:

| Mode | Command | Behavior |
|------|---------|----------|
| **Check** *(default)* | `scan --target <host>` | Passive, read-only security audit. Safe for production. |
| **Simulate** | `scan --target <host> --simulate` | Python modules simulate + YAML atomic tests execute, with automatic cleanup. |
| **Run Atomic** | `run-atomic --target <host> --technique <ID>` | Execute YAML atomic tests directly for a single technique. |

---

## Key Features

- **Dual-mode architecture** -- 29 Python modules (passive check + active simulate) + 202 YAML atomic tests across 61 techniques
- **Atomic Red Team-style YAML tests** -- data-driven test definitions with `#{arg}` templating, dependencies (`prereq_command` / `get_prereq_command`), cleanup commands, and executor types (`powershell`, `command_prompt`, `manual`)
- **Module auto-discovery** -- drop a Python module in `modules/<tactic>/` or a YAML file in `atomics/<technique_id>/` and it is automatically picked up
- **Session abstraction** -- Local execution via subprocess, Remote via WinRM (pypsrp), with SMB/WMI planned
- **ATT&CK Navigator export** -- generates JSON layer files for [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) visualization
- **Multi-format reports** -- HTML (dark theme), JSON, CSV
- **Full evidence chain** -- every action logged with timestamps, target, technique ID, and result
- **Scan profiles** -- quick (8 techniques), full (all), stealth (4 minimal-footprint), or custom YAML
- **OS-aware execution** -- modules declare `SUPPORTED_OS` and auto-skip incompatible targets
- **13 MITRE ATT&CK tactics** -- complete coverage from Reconnaissance through Impact

---

## MITRE ATT&CK Coverage

| Tactic | ID | Python Modules | Atomic YAML Tests | Key Techniques |
|--------|----|:-:|:-:|----------------|
| **Reconnaissance** | TA0043 | 1 | -- | T1595 Active Scanning |
| **Discovery** | TA0007 | 8 | 19 techniques, 73 tests | T1082, T1087, T1069, T1046, T1057, T1016, T1049, T1083, T1033, T1018, T1135, T1482, T1201, T1518.001, T1012, T1007, T1124, T1615, T1614.001 |
| **Execution** | TA0002 | 3 | 6 techniques, 24 tests | T1059.001 PowerShell (7), T1059.003 Command Shell (4), T1047 WMI (4), T1053.005 Scheduled Task (4), T1569.002 Service Execution (3), T1106 Native API (2) |
| **Persistence** | TA0003 | 3 | 7 techniques, 20 tests | T1547.001 Run Keys (4), T1546.003 WMI Event Sub (2), T1546.008 Accessibility Features (3), T1543.003 Windows Service (3), T1136.001 Local Account (3), T1547.004 Winlogon (2) |
| **Privilege Escalation** | TA0004 | 4 | 1 technique, 4 tests | T1548.002 UAC Bypass (4 methods: fodhelper, eventvwr, computerdefaults), T1134, T1574.001, T1574.002 |
| **Defense Evasion** | TA0005 | 4 | 4 techniques, 17 tests | T1562.001 Disable Tools (6), T1562.002 Disable Logging (4), T1112 Modify Registry (4), T1070.001 Clear Logs (3) |
| **Credential Access** | TA0006 | 6 | 6 techniques, 20 tests | T1003.001 LSASS (4), T1003.002 SAM (3), T1003.003 NTDS (3), T1558.003 Kerberoasting (3), T1552.001 Creds in Files (4), T1110.003 Password Spray (3) |
| **Lateral Movement** | TA0008 | -- | 4 techniques, 12 tests | T1021.001 RDP (4), T1021.002 SMB Shares (3), T1021.006 WinRM (3), T1550.002 Pass the Hash (2) |
| **Collection** | TA0009 | -- | 5 techniques, 8 tests | T1113 Screen Capture (2), T1560.001 Archive (2), T1074.001 Staging (1), T1115 Clipboard (1), T1219 RAT Detection (2) |
| **Command & Control** | TA0011 | -- | 3 techniques, 9 tests | T1105 Ingress Transfer (5 methods: WebClient, IWR, certutil, bitsadmin, curl), T1071.001 Web Protocols (2), T1219 Remote Access (2) |
| **Exfiltration** | TA0010 | -- | 1 technique, 3 tests | T1048.003 DNS, ICMP, SMB exfil simulation |
| **Impact** | TA0040 | -- | 5 techniques, 12 tests | T1490 Inhibit Recovery (4), T1489 Service Stop (2), T1529 Shutdown (2), T1485 Data Destruction (2), T1531 Account Access Removal (2) |
| **Total** | | **29 modules** | **61 techniques, 202 tests** | **~90 unique techniques** |

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
# ── Passive scanning (check mode, safe for production) ──────────
python main.py scan --target localhost --profile quick
python main.py scan --target 192.168.1.10 --profile full
python main.py scan --target localhost --tactic discovery
python main.py scan --target localhost --technique T1082

# ── Active simulation (Python modules + YAML atomic tests) ─────
python main.py scan --target 192.168.1.10 --profile full --simulate

# ── Run atomic tests directly for a specific technique ──────────
python main.py run-atomic --target localhost --technique T1082
python main.py run-atomic --target localhost --technique T1059.001 --format json

# ── Module discovery ────────────────────────────────────────────
python main.py list-modules                    # All (Python + atomic)
python main.py list-modules --source python    # Python modules only
python main.py list-modules --source atomic    # YAML atomic tests only

# ── Reporting ───────────────────────────────────────────────────
python main.py scan --target localhost --format json --output report
python main.py scan --target localhost --format html --output report
python main.py report --input reports/scan_20260326.json --format html
```

---

## Architecture

```
Windows-Red-Teaming/
|
|-- main.py                          # CLI entry point (Click)
|
|-- core/                            # Core engine components
|   |-- engine.py                    # ScanEngine — orchestrates Python modules + YAML atomics
|   |-- session.py                   # BaseSession, LocalSession, WinRMSession
|   |-- models.py                    # Target, Finding, ModuleResult, ScanResult, Severity, OSType
|   |-- atomic_models.py             # AtomicTechnique, AtomicTest, InputArgument, Dependency, Executor
|   |-- atomic_runner.py             # YAML atomic test loader, dependency checker, executor, cleanup
|   |-- config.py                    # YAML config loader + profile merging + technique filters
|   |-- logger.py                    # structlog logging + EvidenceLogger audit chain
|   |-- reporter.py                  # HTML (Jinja2) / JSON / CSV report generation
|   +-- mitre_mapper.py             # ATT&CK Navigator v4.5 JSON layer export
|
|-- modules/                         # Python technique modules (check + simulate + cleanup)
|   |-- base.py                      # BaseModule ABC — all modules inherit this
|   |-- reconnaissance/              # TA0043 — 1 module  (T1595)
|   |-- discovery/                   # TA0007 — 8 modules (T1082, T1087, T1069, T1046, T1083, T1057, T1049, T1016)
|   |-- execution/                   # TA0002 — 3 modules (T1059.001, T1059.003, T1047)
|   |-- persistence/                 # TA0003 — 3 modules (T1053.005, T1547.001, T1546.001)
|   |-- privilege_escalation/        # TA0004 — 4 modules (T1548.002, T1134, T1574.001, T1574.002)
|   |-- credential_access/           # TA0006 — 6 modules (T1003.001/.002/.003, T1558.003, T1552.001, T1110)
|   |-- defense_evasion/             # TA0005 — 4 modules (T1562.001/.002, T1036, T1070.001)
|   |-- lateral_movement/            # TA0008 — empty (covered by YAML atomics)
|   |-- collection/                  # TA0009 — empty (covered by YAML atomics)
|   |-- command_and_control/         # TA0011 — empty (covered by YAML atomics)
|   |-- exfiltration/                # TA0010 — empty (covered by YAML atomics)
|   +-- impact/                      # TA0040 — empty (covered by YAML atomics)
|
|-- atomics/                         # YAML atomic tests (Atomic Red Team-style)
|   |-- T1082/T1082.yaml            # 10 tests — System Info Discovery
|   |-- T1087.001/T1087.001.yaml    #  4 tests — Local Account Discovery
|   |-- T1087.002/T1087.002.yaml    #  5 tests — Domain Account Discovery
|   |-- T1059.001/T1059.001.yaml    #  7 tests — PowerShell
|   |-- T1562.001/T1562.001.yaml    #  6 tests — Disable Security Tools
|   |-- T1105/T1105.yaml            #  5 tests — Ingress Tool Transfer
|   +-- ... (61 technique directories, 202 atomic tests total)
|
|-- config/
|   |-- settings.example.yaml        # Template for targets, credentials, output settings
|   |-- techniques.yaml              # Enable/disable individual techniques (99 entries)
|   +-- profiles/
|       |-- quick.yaml               # 8 high-value techniques
|       |-- full.yaml                # All discovered modules
|       +-- stealth.yaml             # 4 minimal-footprint checks
|
|-- templates/
|   +-- report.html                  # Jinja2 dark-themed HTML report template
|
|-- tests/                           # 122 pytest tests
|   |-- conftest.py                  # Shared fixtures (mock_session, sample_target, etc.)
|   |-- test_engine.py               # ScanEngine discovery + authorization tests
|   |-- test_models.py               # Finding, ModuleResult, ScanResult tests
|   |-- test_session.py              # Session abstraction tests
|   |-- test_atomic_models.py        # AtomicTest, InputArgument, Executor, AtomicTechnique tests
|   |-- test_atomic_runner.py        # AtomicRunner discovery, filtering, execution, cleanup tests
|   +-- test_modules/                # Per-module tests (discovery, credential, priv_esc, phase4)
|
|-- evidence/                        # Audit trail storage (gitignored)
|-- reports/                         # Generated reports (gitignored)
+-- docs/                            # Banner SVG
```

### How It Works

```
                    ┌──────────────────────────────────────────────┐
                    |               ScanEngine                     |
                    |                                              |
  scan --target x   |   1. Discover Python modules (modules/)     |
  --simulate        |   2. Discover YAML atomics (atomics/)       |
         |          |   3. Create session (Local or WinRM)         |
         v          |   4. Detect target OS                        |
    ┌────────┐      |   5. Run Python check() on each module      |
    | CLI    |----->|   6. If --simulate: run simulate() + cleanup |
    | main.py|      |   7. If --simulate: run YAML atomic tests   |
    └────────┘      |      for techniques NOT covered by Python    |
                    |   8. Generate reports + ATT&CK layer         |
                    └──────────────────────────────────────────────┘
```

### Python Module Contract (BaseModule)

Every Python technique module inherits from `BaseModule` and implements four methods:

```python
class SystemInfoDiscovery(BaseModule):
    TECHNIQUE_ID   = "T1082"
    TECHNIQUE_NAME = "System Information Discovery"
    TACTIC         = "Discovery"
    SEVERITY       = Severity.MEDIUM
    SUPPORTED_OS   = [OSType.WIN10, OSType.WIN11, OSType.SERVER_2019, OSType.SERVER_2022]
    REQUIRES_ADMIN = False
    SAFE_MODE      = True

    def check(self, session) -> ModuleResult:     # Passive read-only audit
        ...
    def simulate(self, session) -> ModuleResult:  # Active technique demo (--simulate)
        ...
    def cleanup(self, session) -> None:           # Revert simulate changes
        ...
    def get_mitigations(self) -> list[str]:       # Remediation advice
        ...
```

### YAML Atomic Test Format

Atomic tests live in `atomics/<technique_id>/<technique_id>.yaml`. Each file can define multiple tests for one ATT&CK technique, inspired by [Red Canary's Atomic Red Team](https://github.com/redcanaryco/atomic-red-team):

```yaml
attack_technique: T1082
display_name: "System Information Discovery"
tactic: Discovery
atomic_tests:
  - name: "System Information via systeminfo"
    auto_generated_guid: a0f7e4b1c2d3e4f5a6b7c8d9e0f1a2b3
    description: |
      Executes systeminfo to gather OS version and hardware details.
    supported_platforms:
      - windows
    input_arguments:                      # #{arg} templating in commands
      output_file:
        description: "Output file path"
        type: path
        default: "%TEMP%\\sysinfo.txt"
    dependencies:                         # Pre-flight checks
      - description: "Tool must exist"
        prereq_command: "where systeminfo"
        get_prereq_command: null           # null = manual resolution
    executor:
      name: command_prompt                 # powershell | command_prompt | manual
      command: |
        systeminfo > #{output_file}
      cleanup_command: |
        del /f #{output_file} >nul 2>&1
      elevation_required: false
```

**Key features:**
- `#{arg_name}` substitution with defaults and CLI overrides
- Dependency system: `prereq_command` (exits 0 if met) + optional `get_prereq_command` (auto-install)
- Three executor types: `powershell`, `command_prompt`, `manual` (human steps)
- Cleanup commands run automatically after each test
- `elevation_required` flag for tests needing admin privileges

---

## Scan Profiles

| Profile | Tactics | Techniques | Use Case |
|---------|---------|------------|----------|
| `quick` | Discovery, Credential Access, Defense Evasion | 8 high-value | Fast security posture check |
| `full` | All enabled | All discovered | Comprehensive passive audit |
| `stealth` | Discovery, Defense Evasion | 4 minimal | Low-footprint reconnaissance |

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

- Targets must be explicitly configured in `config/settings.yaml`
- Default mode is **check-only** (passive, read-only)
- Active simulation requires the explicit `--simulate` CLI flag
- Authorization banner displayed and confirmed before every scan
- Every action produces a timestamped audit log entry in `evidence/`
- `cleanup()` / `cleanup_command` runs automatically after every simulation
- Python modules auto-skip if the target OS is not in `SUPPORTED_OS`
- YAML atomic tests with `elevation_required: true` are flagged in output

---

## Development

### Running Tests

```bash
pip install pytest pytest-mock pytest-cov
python -m pytest tests/ -v                    # All 122 tests
python -m pytest tests/test_atomic_runner.py  # Atomic framework only
python -m pytest tests/test_modules/ -v       # Module tests only
```

### Adding a New Python Module

1. Create `modules/<tactic>/T{ID}_{name}.py`
2. Inherit from `BaseModule`, set all required class attributes
3. Implement `check()`, `simulate()`, `cleanup()`, `get_mitigations()`
4. Add tests in `tests/test_modules/`
5. The engine auto-discovers it on the next run

### Adding a New YAML Atomic Test

1. Create `atomics/T{ID}/T{ID}.yaml`
2. Define `attack_technique`, `display_name`, `tactic`, and `atomic_tests` list
3. Each test needs: `name`, `description`, `supported_platforms: [windows]`, `executor`
4. Add `cleanup_command` for any test that modifies system state
5. Add `input_arguments` with sensible defaults for parameterized tests
6. The atomic runner auto-discovers it on the next run

### Roadmap

- [x] **Phase 1** -- Foundation (engine, sessions, CLI, config, logging, reporting)
- [x] **Phase 2** -- Discovery & Reconnaissance (9 Python modules)
- [x] **Phase 3** -- Credential Access & Privilege Escalation (10 Python modules)
- [x] **Phase 4** -- Execution, Persistence & Defense Evasion (10 Python modules)
- [x] **Phase 5** -- Atomic test library (61 techniques, 202 YAML tests, all 13 tactics)
- [ ] **Phase 6** -- Per-technique detail pages, CIS/NIST mapping
- [ ] **Phase 7** -- Integration tests, CI/CD pipeline, user documentation

---

## License

[MIT License](LICENSE) -- Copyright (c) 2026 KRISH

---

<p align="center">
  <sub>Built for authorized security testing and red team assessments only.</sub>
</p>

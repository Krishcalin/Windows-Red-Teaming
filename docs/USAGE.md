# Windows Red Teaming Tool — User Guide

A MITRE ATT&CK–aligned active scanning tool for **authorized** red team testing on
Windows systems. It combines deep Python audit modules with a broad library of
YAML-based atomic tests (Atomic Red Team style), and produces HTML / JSON / CSV /
ATT&CK Navigator / compliance reports.

> **Authorization is mandatory.** Only run this tool against systems you own or are
> explicitly contracted to test. Every scan displays an authorization banner and
> requires confirmation. Unauthorized use is illegal.

---

## 1. Installation

Requires **Python 3.10+**.

```bash
git clone https://github.com/Krishcalin/Windows-Red-Teaming.git
cd Windows-Red-Teaming

python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
```

Verify the install:

```bash
python main.py --version
python main.py list-modules
```

---

## 2. Configuration

### 2.1 Global settings

Copy the template and edit it for your environment. `settings.yaml` is gitignored —
**never commit credentials**.

```bash
cp config/settings.example.yaml config/settings.yaml
```

Key sections (`config/settings.example.yaml`):

| Section | Purpose |
|---------|---------|
| `targets` | Whitelisted hosts. `connection` is one of `local`, `winrm`, `smb`, `wmi`. |
| `default_profile` | `quick`, `full`, or `stealth`. |
| `output` | `report_dir`, `evidence_dir`, report `formats`, `attack_layer` toggle. |
| `logging` | `verbose`, `log_file`, `json_output`. |
| `safety` | `require_authorization_banner`, `max_concurrent_modules`. |

A target whitelist entry looks like:

```yaml
targets:
  - host: "192.168.1.10"
    connection: "winrm"
    port: 5985
    domain: "CORP"
    username: "redteam"
    password: ""          # prefer env injection over committing secrets
    use_kerberos: false
    ssl: false
  - host: "localhost"
    connection: "local"
```

### 2.2 Profiles

Profiles live in `config/profiles/` and select which techniques run:

| Profile   | Scope |
|-----------|-------|
| `quick`   | 8 high-value techniques (fast triage). |
| `full`    | All discovered Python modules + atomics. |
| `stealth` | 4 minimal-footprint checks. |

### 2.3 Technique allow/deny

`config/techniques.yaml` enables or disables individual ATT&CK techniques globally.
This applies on top of the selected profile.

---

## 3. Execution modes

The tool has three escalating modes. **Start with dry-run, then check, and only
use simulate with explicit authorization.**

| Mode | Flag | System impact | What runs |
|------|------|---------------|-----------|
| **Dry-run** | `--dry-run` | None — no connection, no commands | Prints the exact plan only |
| **Check** (default) | *(none)* | Read-only | Python module `check()` |
| **Simulate** | `--simulate` | Active (with cleanup) | `check()` + `simulate()` + `cleanup()` + atomic tests |

### 3.1 Dry-run — preview before you touch anything

Dry-run resolves your profile/tactic/technique filters and prints exactly which
Python modules and atomic tests *would* run — **without connecting to the target or
executing a single command.** Use it to validate scope before every engagement.

```bash
# Preview a quick check-mode scan
python main.py scan --target 192.168.1.10 --profile quick --dry-run

# Preview a full active simulation (atomic tests included in the plan)
python main.py scan --target 192.168.1.10 --profile full --simulate --dry-run

# Preview a single technique
python main.py scan --target 192.168.1.10 --technique T1059.001 --simulate --dry-run
```

The plan shows, per module, the **planned actions**:

- `check (read-only)` — passive only
- `check (safe-mode: simulate skipped)` — module declares `SAFE_MODE`, so simulate
  is suppressed even under `--simulate`
- `check + simulate + cleanup` — full active lifecycle

> OS-compatibility guards (`SUPPORTED_OS`) are evaluated at runtime against the live
> target, so modules unsupported on the target OS are skipped during the real scan,
> not in the dry-run plan.

### 3.2 Check mode (default) — passive audit

```bash
python main.py scan --target localhost --profile quick
python main.py scan --target 192.168.1.10 --profile full
python main.py scan --target localhost --tactic discovery
python main.py scan --target localhost --technique T1082
```

### 3.3 Simulate mode — active testing

Requires the explicit `--simulate` flag. Runs Python `simulate()` methods **and** the
YAML atomic tests, each followed automatically by cleanup/rollback.

```bash
python main.py scan --target 192.168.1.10 --profile full --simulate
```

---

## 4. Commands

### `scan`

Run a security scan against a target.

| Option | Description |
|--------|-------------|
| `-t, --target` | Target host (IP, hostname, or `localhost`). **Required.** |
| `-p, --profile` | `quick` \| `full` \| `stealth` (default `full`). |
| `-s, --simulate` | Enable active simulation. |
| `--dry-run` | Preview the plan without connecting or executing. |
| `--tactic` | Filter to one ATT&CK tactic (e.g. `discovery`). |
| `--technique` | Filter to one technique ID (e.g. `T1082`). |
| `-o, --output` | Output report filename (without extension). |
| `-f, --format` | `html` \| `json` \| `csv` \| `compliance` (repeatable). |
| `--severity` | Minimum severity threshold (`CRITICAL`…`INFO`). |
| `-v, --verbose` | Verbose logging. |

**Exit codes:** `1` if any CRITICAL/HIGH finding is present, else `0` — useful for CI gates.

### `list-modules`

```bash
python main.py list-modules                 # Python + atomic
python main.py list-modules --source python
python main.py list-modules --source atomic
```

### `run-atomic`

Run the YAML atomic tests for a single technique (simulate semantics; prompts for
authorization).

```bash
python main.py run-atomic --target localhost --technique T1082
python main.py run-atomic --target localhost --technique T1059.001 --format json -o t1059
```

### `report`

Regenerate a report from a previous scan's JSON output.

```bash
python main.py report --input reports/scan_20260326.json --format html
python main.py report --input reports/scan_20260326.json --format attack-layer
python main.py report --input reports/scan_20260326.json --format compliance
```

---

## 5. Outputs

| Output | Location | Notes |
|--------|----------|-------|
| HTML report | `reports/` | Dark-themed, executive summary + Chart.js dashboard. |
| JSON report | `reports/` | Machine-readable, full findings. |
| CSV report | `reports/` | One row per finding. |
| ATT&CK layer | `reports/` | Import into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/). |
| Compliance | `reports/` | CIS Benchmark / NIST 800-53 mappings. |
| Evidence chain | `evidence/` | Timestamped audit trail of every action. |

Both `reports/` and `evidence/` are gitignored.

---

## 6. Safety controls

- **Whitelist required** — targets must be configured before scanning.
- **Check-only by default** — active behavior requires `--simulate`.
- **Dry-run** — `--dry-run` previews scope with zero target contact.
- **Authorization banner** — shown and confirmed before any scan/atomic run.
- **Automatic cleanup/rollback** — `cleanup()` and atomic `cleanup_command` run after
  every simulation, even if the simulation raises.
- **OS guard** — modules auto-skip on unsupported target OS.
- **`SAFE_MODE` modules** — never execute `simulate()` even under `--simulate`.
- **Evidence chain** — every action is recorded in `evidence/`.

---

## 7. Typical workflow

```bash
# 1. Scope check — confirm exactly what will run, contact nothing
python main.py scan --target 192.168.1.10 --profile full --simulate --dry-run

# 2. Passive baseline — read-only audit
python main.py scan --target 192.168.1.10 --profile full -f html -f json

# 3. Active simulation — only with written authorization
python main.py scan --target 192.168.1.10 --profile full --simulate -f html

# 4. Share results — ATT&CK Navigator layer + compliance mapping
python main.py report --input reports/<scan>.json --format attack-layer
python main.py report --input reports/<scan>.json --format compliance
```

---

## 8. Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `No targets configured` | Add the host to `config/settings.yaml` or pass `--target`. |
| WinRM connection fails | Enable WinRM on the target; check port `5985`/`5986`, firewall, and credentials. |
| Modules skipped | Target OS not in the module's `SUPPORTED_OS`, or technique disabled in `config/techniques.yaml`. |
| Atomic tests don't run | They run only in `--simulate` mode (or via `run-atomic`). |
| Permission errors during checks | Some checks need admin; run from an elevated session. |

For deeper architecture details see [CLAUDE.md](../CLAUDE.md).

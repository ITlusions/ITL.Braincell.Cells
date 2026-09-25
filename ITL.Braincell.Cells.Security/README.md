# ITL BrainCell Cells — Security & Threat Intelligence

A plugin package for BrainCell that provides security-focused memory cells for threat intelligence, incident tracking, vulnerability management, and comprehensive offensive/defensive analysis.

## 🎯 First Operational Goal

**Automated Daily Scanning of Top 100 GitHub Repositories for Vulnerabilities**

Use the AI agent to autonomously discover, analyze, and report security vulnerabilities in the most widely-used open-source software on GitHub.

See [AUTOMATED-GITHUB-SCANNING-WORKFLOW.md](AUTOMATED-GITHUB-SCANNING-WORKFLOW.md) for:
- Complete workflow architecture
- 6-phase agent execution pipeline (discovery → scanning → analysis → correlation → reporting)
- Implementation timeline (2-3 weeks)
- Scheduled daily scans with alerting
- Sample queries and results

**What this achieves:**
- ✅ Scans 100 repositories daily (4-6 hours)
- ✅ Finds 400+ vulnerabilities per day
- ✅ Ranks by exploitability and blast radius
- ✅ Generates daily report with recommendations
- ✅ Links to patches, CVEs, proof-of-concepts
- ✅ Alerts security team for critical findings

**Uses Phases 1-3 of the roadmap** (Dependency + SAST + Binary Analysis)

---

## Architecture

Built on the **4-layer BrainCell architecture**:

```
Layer 4: MCP Tools          → LLM/Agent Interface
Layer 3: Security Cells     → Domain-specific implementations
Layer 2: BrainCell Core     → Cell discovery & data warehouse
Layer 1: SDK                → ORM models & service logic
```

**How it works:**
1. **SDK** defines ORM models (BinaryAnalysis, FuzzCrash, RuntimeAnalysis, etc.) and service classes
2. **Core** auto-discovers cells via MemoryCell plugin mechanism
3. **Plugin** (this package) implements cells that extend schema and add routes
4. **MCP** wraps service methods as callable tools for Claude/Agents

## Included Cells

**Threat Intelligence (Existing):**
- **threats** — Threat actor profiles, APTs, criminal groups, MITRE ATT&CK TTPs
- **incidents** — Security incident tracking and timeline
- **iocs** — Indicators of Compromise (IPs, domains, hashes, etc.)

**Analysis Cells (Documented/In Development):**
- **binary_analysis** — Reverse engineering (Ghidra, Radare2, Angr)
- **rop_gadgets** — ROP chain exploitation
- **fuzz_testing** — Crash discovery & exploitability analysis
- **runtime_monitoring** — Dynamic behavior analysis (APIs, syscalls, taint)
- **network_analysis** — C2 protocol extraction & beacon detection
- **malware_family** — Sample clustering & variant tracking
- **sast** — Static code analysis (Semgrep, Bandit, SonarQube)
- **dependencies** — Dependency scanning (Safety, Trivy)
- **supply_chain** — Dependency graph & compromise path analysis
- **configuration** — Security misconfiguration detection
- **access_control** — Privilege escalation path analysis
- **cryptography** — Encryption & key strength validation
- **hypothesis_testing** — PoC validation & reliability measurement
- **defense_validation** — Test defense effectiveness

**Attack Framework Cells:**
- **kill_chains** — Attack progression tracking (7-phase model)
- **red_team** — Offensive operation planning & reporting
- **blue_team** — Defensive strategy & coverage analysis

## Installation

### Local Development
```bash
cd d:\repos\itl-braincell-cells-security
pip install -e .
```

### From PyPI
```bash
pip install itl-braincell-cells-security
```

After installation, cells are automatically discovered when the BrainCell API/MCP server starts.

## Usage

Cells expose REST endpoints and MCP tools:

### REST API Examples

```bash
# Search threats
curl http://localhost:9504/api/threats?q=APT28

# Create incident
curl -X POST http://localhost:9504/api/incidents \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Potential breach detected",
    "severity": "high",
    "description": "Unusual login patterns detected"
  }'

# Search IOCs
curl http://localhost:9504/api/iocs?q=malware.example.com

# List vulnerabilities
curl http://localhost:9504/api/vuln-reports?severity=critical
```

### MCP Tools

Each cell registers tools in the MCP server:

- `threats_search(query, limit)` — Find threat actors
- `incidents_create(title, severity, description)` — Log incident
- `iocs_search(query)` — Search indicators
- `vuln_reports_search(query)` — Find vulnerabilities
- `kill_chains_search(query)` — Search attack patterns

## Database

Each cell requires its corresponding table:

- `threats` (ThreatActor rows)
- `incidents` (Incident rows)
- `iocs` (IOC rows)
- `intel_reports` (IntelReport rows)
- `kill_chains` (KillChain rows)
- `vuln_reports` (VulnReport rows)
- `vuln_patches` (VulnPatch rows)

Run migrations after install:

```bash
cd ../ITL.BrainCell.Api
alembic upgrade head
```

## Integration with Other Cells

This plugin integrates with:

- **dependencies** cell — cross-reference vulnerabilities to packages
- **errors** cell — link incidents to errors
- **decisions** cell — document security decisions
- **runbooks** cell — link procedures to threat responses

---

## Security Analysis Tools (Roadmap)

For comprehensive security analysis including binary reverse engineering and static code analysis:

See [SECURITY-ANALYSIS-GUIDE.md](SECURITY-ANALYSIS-GUIDE.md) for:

- **Binary Analysis** — Ghidra, Radare2, Angr integration
- **ROP Chain Analysis** — Radare2, Ropper, Angr for exploitation
  - ROP gadget discovery
  - Automated chain building
  - Exploitation feasibility assessment
  - Threat actor correlation
- **Fuzz Testing & Crash Analysis** — AFL++, libFuzzer, Honggfuzz
  - Detect buffer overflow, format string, use-after-free patterns
  - Automatically generate fuzzing corpus
  - Launch automated fuzz campaigns (hours to days)
  - Analyze discovered crashes for exploitability
  - Automatic crash deduplication and triage
  - Build ROP chain exploits from crashes
  - Correlate fuzzing results to kill chain exploitation phase
- **Static Code Analysis** — Semgrep, Bandit, SonarQube, Trivy
- **Dependency Scanning** — Safety, Snyk, OWASP Dependency-Check
- **Kill Chain Building & Monitoring**
  - Build custom attack scenarios phase-by-phase
  - Track kill chain state (predicted → in_progress → detected → blocked)
  - Real-time phase transition monitoring
  - Automated alerts when phases advance
  - Predict timing of next phases
  - Timeline visualization
  - Playbook-based attack scenarios
  - Incident integration for full context
- **Red Team (Offensive) Operations**
  - Plan authorized penetration tests with kill chains
  - Track operation progress phase-by-phase
  - Document findings and security gaps
  - Generate executive red team reports
- **Blue Team (Defensive) Strategy**
  - Prevention controls for each attack phase
  - Detection rules (SIEM, EDR, WAF, DLP)
  - Incident response procedures
  - Deception tactics (honeypots, canaries)
  - Defense coverage reports
  - Identify gaps and generate remediation roadmap
- **Integrated Workflows**
  - Execute red team attacks, then build defenses
  - Cover all 7 attack phases with multi-layer protection
  - Track offensive/defensive effectiveness
- **Data Models** — BinaryAnalysis, SASTFinding, DependencyScan, KillChain, FuzzTestRun, FuzzCrash
- **MCP Tools** — Unified analysis interface for Claude
- **Integration Patterns** — Cross-reference with threats & vulnerabilities
- **Deployment** — Docker setup and quick start guide

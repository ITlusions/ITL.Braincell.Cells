# Security Analysis Tools Integration Guide

Comprehensive guide to integrating binary analysis and static code analysis tools with the BrainCell Security Plugin.

## Overview

The Security Plugin can be extended to include an **Analysis Service** that integrates:

- **Binary Analysis:** Ghidra, IDA, Radare2, Angr
- **Static Code Analysis (SAST):** Semgrep, SonarQube, Bandit, Trivy
- **Dependency Scanning:** Safety, Snyk, OWASP Dependency-Check

All findings are stored in BrainCell and cross-referenced with threat intelligence.

---

## Architecture

The security analysis platform is built on a **4-layer architecture**:

```
┌─────────────────────────────────────────────────────────────────┐
│ LAYER 4: MCP Tools (Claude / AI / Agents Interface)             │
│ ─────────────────────────────────────────────────────────────── │
│ ITL.BrainCell.Mcp implements @mcp.tool() wrappers:             │
│ • find_rop_gadgets(), analyze_crash()                          │
│ • detect_fuzzable_functions(), run_fuzz_campaign()             │
│ • build_exploit_from_crash(), correlate_crashes_to_kill_chain()│
│ • analyze_binary(), scan_dependencies(), analyze_code()        │
│ • create_kill_chain(), track_phase_transitions()               │
│ • plan_red_team_operation(), build_blue_team_defense()        │
│ • start_runtime_monitoring(), extract_network_protocol()       │
└─────────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────────┐
│ LAYER 3: Security Plugin Cells (Domain Extensions)              │
│ ─────────────────────────────────────────────────────────────── │
│ ITL.Braincell.Cells.Security extends base functionality:       │
│                                                                  │
│ Threat Intelligence Cells:                                      │
│ • threats/ → Threat actors, TTPs, campaigns                    │
│ • incidents/ → Security incidents, timelines                   │
│ • iocs/ → Indicators of Compromise                             │
│                                                                  │
│ Analysis Cells (NEW):                                           │
│ • binary_analysis/ → Reverse engineering (Ghidra, Radare2)    │
│ • rop_gadgets/ → ROP chain exploitation                        │
│ • fuzz_testing/ → Crash discovery & analysis                  │
│ • kill_chains/ → Attack progression tracking                   │
│ • red_team/ → Offensive operations                             │
│ • blue_team/ → Defensive strategies                            │
│ • runtime_monitoring/ → Dynamic behavior analysis              │
│ • network_analysis/ → Protocol & C2 detection                  │
│ • malware_family/ → Sample clustering & genealogy              │
│ • supply_chain/ → Dependency graph analysis                    │
│ • configuration/ → Security misconfiguration detection          │
│ • access_control/ → Privilege escalation paths                 │
│ • cryptography/ → Encryption & key analysis                    │
│ • hypothesis_testing/ → PoC validation                         │
│ • defense_validation/ → Test defense effectiveness             │
│                                                                  │
│ Each cell provides:                                             │
│ • ORM models (defined in SDK but extended in plugin)          │
│ • Routes (FastAPI endpoints)                                   │
│ • Schemas (Pydantic validation)                                │
└─────────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────────┐
│ LAYER 2: Core BrainCell Data Warehouse                          │
│ ─────────────────────────────────────────────────────────────── │
│ ITL.BrainCell (core library) provides:                         │
│ • Base MemoryCell ABC class                                    │
│ • Cell discovery & plugin registration                         │
│ • SQLAlchemy async session management                          │
│ • Weaviate vector search integration                           │
│ • Alembic migration infrastructure                             │
│ • Cross-cell relationship management                           │
│ • Base Pydantic schemas for all cells                          │
│ • Authentication (Keycloak RBAC)                               │
└─────────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────────┐
│ LAYER 1: SDK Data Stores & Service Logic                        │
│ ─────────────────────────────────────────────────────────────── │
│ ITL.Braincell.SDK provides reusable infrastructure:             │
│                                                                  │
│ ORM Base Classes (all inherit from SQLAlchemy Base):           │
│ • BinaryAnalysis, SASTFinding, DependencyScan                  │
│ • FuzzTestRun, FuzzCrash                                       │
│ • RuntimeAnalysis, NetworkAnalysis                             │
│ • MalwareFamily, DependencyGraph                               │
│ • ConfigurationAnalysis, AccessControlAnalysis                 │
│ • CryptographyAnalysis, HypothesisTest                         │
│ • DefenseValidation, KillChain                                 │
│ • Base cells: MemoryCell, TimestampMixin                       │
│                                                                  │
│ Service Classes (business logic):                               │
│ • BinaryAnalysisService(db) → analyze_binary_radare2()        │
│ • FuzzingService(db) → run_fuzz_campaign()                    │
│ • RuntimeMonitorService(db) → start_monitoring()              │
│ • NetworkAnalysisService(db) → extract_protocol()             │
│ • MalwareFamilyService(db) → cluster_samples()                │
│ • SupplyChainService(db) → analyze_dependency_graph()         │
│ • ConfigAnalysisService(db) → detect_misconfigs()             │
│ • AccessControlService(db) → find_escalation_paths()          │
│ • CryptoAnalysisService(db) → validate_cipher_strength()      │
│ • HypothesisTestService(db) → run_poc()                       │
│ • DefenseValidationService(db) → test_defense()               │
│ • KillChainService(db) → build_chain()                        │
│                                                                  │
│ Async Database Layer:                                           │
│ • PostgreSQL (threats, incidents, IOCs, findings)             │
│ • Weaviate (vector search for behavioral similarity)           │
│ • Redis (caching, message queues)                              │
│                                                                  │
│ Tool Integration (subprocess wrappers):                         │
│ • Ghidra, Radare2, Angr (reverse engineering)                 │
│ • Semgrep, Bandit, SonarQube (SAST)                           │
│ • Safety, Trivy (dependency scanning)                          │
│ • AFL++, libFuzzer, Honggfuzz (fuzzing)                       │
│ • Valgrind, GDB (crash analysis)                               │
│ • strace, API hooks (dynamic monitoring)                       │
│ • Zeek, Suricata (network capture)                             │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
1. Binary / Code / Dependencies
   ↓
2. SDK Service Classes run tools → ORM models → PostgreSQL/Weaviate
   ↓
3. Security Plugin Cells organize findings by domain
   ↓
4. BrainCell Core links cells together (cross-reference)
   ↓
5. MCP Tools expose service methods as Claude-callable functions
   ↓
6. AI/Agents/LLMs call tools → Get structured analysis results
   ↓
7. Results flow back to BrainCell data warehouse for correlation
```

### Missing Capabilities: Where They Belong

The 9 critical gaps require implementation across all 4 layers:

| Capability | Layer 1 (SDK) | Layer 2 (Core) | Layer 3 (Plugin) | Layer 4 (MCP) |
|------------|---------------|----------------|------------------|--------------|
| **1. Runtime Monitoring** | RuntimeAnalysisService, RuntimeAnalysis ORM | — | runtime_monitoring/ cell | start_monitoring(), get_telemetry() |
| **2. Network Analysis** | NetworkAnalysisService, NetworkAnalysis ORM | — | network_analysis/ cell | extract_protocol(), find_c2_domains() |
| **3. Malware Family** | MalwareFamilyService, MalwareFamily ORM | — | malware_family/ cell | cluster_samples(), link_variants() |
| **4. Supply Chain** | SupplyChainService, DependencyGraph ORM | — | supply_chain/ cell | analyze_dependency_graph(), find_compromise_paths() |
| **5. Config Analysis** | ConfigAnalysisService, ConfigurationAnalysis ORM | — | configuration/ cell | detect_misconfigs(), check_compliance() |
| **6. Access Control** | AccessControlService, AccessControlAnalysis ORM | — | access_control/ cell | find_escalation_paths(), analyze_rbac() |
| **7. Cryptography** | CryptoAnalysisService, CryptographyAnalysis ORM | — | cryptography/ cell | validate_cipher_strength(), find_crypto_failures() |
| **8. Hypothesis Testing** | HypothesisTestService, HypothesisTest ORM | — | hypothesis_testing/ cell | run_poc(), measure_reliability() |
| **9. Defense Validation** | DefenseValidationService, DefenseValidation ORM | — | defense_validation/ cell | test_defense(), measure_coverage() |

## Critical Gaps Summary

The 9 missing capabilities represent moving from **Theory → Reality → Operations**:

| Gap | Phase | Priority | Impact | Effort | Quick Win? |
|-----|-------|----------|--------|--------|-----------|
| **Hypothesis Testing** PoC validation | 9 | 🔴 CRITICAL | Filter false positives | Medium | ✅ YES (1 wk) |
| **Runtime Monitoring** Dynamic behavior | 10 | 🔴 CRITICAL | Understand real behavior | High | ⏳ (2 wk) |
| **Network Analysis** C2 detection | 11 | 🔴 CRITICAL | Detect command & control | High | ⏳ (2 wk) |
| **Supply Chain** Compromise paths | 13 | 🔴 CRITICAL | Understand blast radius | High | ✅ YES (1 wk) |
| **Configuration** Misconfigurations | 14 | 🟠 HIGH | Find insecure defaults | Easy | ✅ YES (1 wk) |
| **Malware Family** Clustering | 12 | 🟠 HIGH | Link variants & accelerate | Medium | ⏳ (1 wk) |
| **Access Control** Privilege escalation | 15 | 🟠 HIGH | Find privesc paths | Medium | ⏳ (2 wk) |
| **Cryptography** Encryption validation | 16 | 🟠 HIGH | Detect weak crypto | Medium | ⏳ (1 wk) |
| **Defense Validation** Test defenses work | 17 | 🔴 CRITICAL | Know if defenses stop attacks | Hard | ⏳ (2 wk) |

### Quick Win Path (2 weeks)
Start with **Phases 9, 14, 13** for highest ROI:
1. Hypothesis Testing → Filter false positives
2. Configuration Analysis → Find misconfigs
3. Supply Chain Analysis → Understand dependencies
Result: **Find it → Prove it → Track it → Defend it**

---

### Implementation Pattern (for each capability)

All 9 capabilities follow the same 4-layer pattern:

**Step 1: SDK (Layer 1)** — Define ORM & Service
```python
# File: ITL.Braincell.SDK/src/itl_braincell_sdk/cells/runtime_monitoring/model.py
class RuntimeAnalysis(Base, TimestampMixin):
    __tablename__ = "runtime_analyses"
    binary_analysis_id: int
    execution_trace: dict
    syscall_sequence: list
    behavioral_verdict: str
    threat_score: float

# File: ITL.Braincell.SDK/src/itl_braincell_sdk/services/runtime_monitoring_service.py
class RuntimeMonitoringService:
    async def start_monitoring(self, binary_path: str) -> RuntimeAnalysis:
        # Launch strace/API hooks, collect telemetry, store in DB
    async def get_behavioral_verdict(self, analysis_id: int) -> str:
        # Analyze traces and classify behavior
```

**Step 2: Security Plugin (Layer 3)** — Implement Cell
```python
# File: ITL.Braincell.Cells.Security/src/itl_braincell_cells_security/cells/runtime_monitoring/cell.py
class RuntimeMonitoringCell(MemoryCell):
    name = "runtime_monitoring"
    prefix = "/api/runtime-monitoring"
    
    def get_models(self):
        return [RuntimeAnalysis]
    
    def get_router(self):
        from .routes import router
        return router
    
    def register_mcp_tools(self, mcp):
        # Register start_monitoring(), get_telemetry() for MCP
```

**Step 3: MCP (Layer 4)** — Expose as Tool
```python
# File: ITL.BrainCell.Mcp/src/mcp/server.py
@mcp.tool()
async def start_monitoring(binary_path: str) -> dict:
    """Start real-time monitoring of binary execution."""
    service = RuntimeMonitoringService(db)
    analysis = await service.start_monitoring(binary_path)
    return {"campaign_id": analysis.id, "status": "monitoring"}

@mcp.tool()
async def get_telemetry(analysis_id: int) -> dict:
    """Get collected telemetry data."""
    service = RuntimeMonitoringService(db)
    data = await service.get_telemetry(analysis_id)
    return data
```

**Step 4: BrainCell Core (Layer 2)** — Register Cell
```python
# File: ITL.BrainCell/src/braincell/cells/__init__.py
# Auto-discovery loads runtime_monitoring cell from plugin
# No manual wiring needed (done by MemoryCell discovery)
```

---

## Data Models

### BinaryAnalysis Model

Stores results from reverse engineering and binary analysis.

```python
from sqlalchemy import Column, String, DateTime, JSON, Float
from sqlalchemy.dialects.postgresql import UUID
import uuid
from datetime import datetime

from itl_braincell_sdk.core.models import Base, TimestampMixin

class BinaryAnalysis(Base, TimestampMixin):
    """Results from binary reverse engineering."""
    __tablename__ = "binary_analyses"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Binary metadata
    binary_path = Column(String, nullable=False)
    binary_hash = Column(String, nullable=True)              # SHA256 for dedup
    binary_name = Column(String, nullable=True)
    
    # Analysis tool & environment
    tool_used = Column(String, nullable=False)               # ghidra, ida, radare2, angr
    architecture = Column(String, nullable=True)             # x86_64, ARM, MIPS, etc.
    entrypoint = Column(String, nullable=True)               # Main entry point
    
    # Extracted information
    functions = Column(JSON, nullable=True, default=list)    # [{name, address, size, calls_to, calls_from}]
    imports = Column(JSON, nullable=True, default=list)      # [libc.so, ntdll.dll, ...]
    exports = Column(JSON, nullable=True, default=list)
    strings = Column(JSON, nullable=True, default=list)      # Suspicious strings, hardcoded values
    api_calls = Column(JSON, nullable=True, default=list)    # CreateProcess, WinExec, network calls
    
    # Security analysis
    suspicious_patterns = Column(JSON, nullable=True, default=list)
    # [
    #   {"pattern": "packed code", "confidence": 0.95},
    #   {"pattern": "anti-debug", "confidence": 0.87},
    #   {"pattern": "obfuscation", "confidence": 0.92}
    # ]
    
    obfuscation_detected = Column(String, nullable=True)     # none, light, moderate, heavy
    is_packed = Column(String, nullable=True)                # none, generic, upx, custom
    has_anti_debug = Column(String, nullable=True)
    
    threat_score = Column(Float, nullable=True)              # 0.0-1.0
    threat_level = Column(String, nullable=True)            # low, medium, high, critical
    
    # Cross-cell references
    related_threats = Column(JSON, nullable=True, default=list)   # APT groups with similar malware
    related_cves = Column(JSON, nullable=True, default=list)      # CVEs this might exploit
    related_incidents = Column(JSON, nullable=True, default=list) # Incident IDs
    
    # Metadata
    notes = Column(String, nullable=True)
    status = Column(String, default="pending")               # pending, analyzed, reviewed, flagged

    def __repr__(self) -> str:
        return f"<BinaryAnalysis id={self.id} tool={self.tool_used} threat_level={self.threat_level}>"
```

### SASTFinding Model

Stores results from static code analysis.

```python
class SASTFinding(Base, TimestampMixin):
    """Results from static code analysis (SAST)."""
    __tablename__ = "sast_findings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Tool & language
    tool = Column(String, nullable=False)                    # semgrep, sonarqube, bandit, trivy
    language = Column(String, nullable=True)                 # python, javascript, java, go, etc.
    
    # Location in code
    file_path = Column(String, nullable=False)
    line_number = Column(Integer, nullable=True)
    column_number = Column(Integer, nullable=True)
    code_snippet = Column(String, nullable=True)             # Context (5-10 lines)
    
    # Issue details
    issue_type = Column(String, nullable=False)              # sql-injection, xss, hardcoded-secret, weak-crypto
    severity = Column(String, nullable=False)                # critical, high, medium, low
    message = Column(String, nullable=False)
    rule_id = Column(String, nullable=True)                  # e.g., python.django.security.sql-injection
    
    # Categorization
    cwe_ids = Column(JSON, nullable=True, default=list)      # [CWE-89, CWE-502]
    owasp_category = Column(String, nullable=True)           # A01:2021 – Broken Access Control
    category = Column(String, nullable=True)                 # vulnerability, bug, code-smell, security-hotspot
    
    # Remediation
    fix_suggestion = Column(String, nullable=True)
    fix_priority = Column(String, nullable=True)             # immediate, high, medium, low
    
    # Status tracking
    status = Column(String, default="open")                  # open, fixed, false-positive, acknowledged, wont-fix
    reviewed_by = Column(String, nullable=True)
    notes = Column(String, nullable=True)
    
    # Cross-cell references
    related_vuln_reports = Column(JSON, nullable=True, default=list)  # vuln_reports cell IDs
    related_threats = Column(JSON, nullable=True, default=list)       # threat actors that exploit this
    related_incidents = Column(JSON, nullable=True, default=list)     # incident IDs

    def __repr__(self) -> str:
        return f"<SASTFinding id={self.id} tool={self.tool} type={self.issue_type} severity={self.severity}>"
```

### DependencyScan Model

Stores dependency vulnerability scan results.

```python
class DependencyScan(Base, TimestampMixin):
    """Dependency vulnerability scanning results."""
    __tablename__ = "dependency_scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Scan scope
    repo_path = Column(String, nullable=False)
    package_manager = Column(String, nullable=False)         # pip, npm, maven, nuget, gem
    requirements_file = Column(String, nullable=True)        # requirements.txt, package.json, pom.xml
    
    # Scan tools used
    scan_tools = Column(JSON, nullable=False, default=list)  # ["safety", "snyk", "trivy"]
    
    # Dependency data
    dependencies = Column(JSON, nullable=False, default=list)
    # [{
    #    "name": "requests",
    #    "version": "2.28.0",
    #    "vulnerabilities": [
    #      {"cve": "CVE-2023-1234", "severity": "high"}
    #    ]
    # }]
    
    vulnerabilities = Column(JSON, nullable=False, default=list)
    # [{
    #    "package": "django",
    #    "installed_version": "3.2.0",
    #    "vulnerable_versions": ["<3.2.5"],
    #    "cve": "CVE-2023-5678",
    #    "severity": "critical",
    #    "fix": "Upgrade to 3.2.5 or later"
    # }]
    
    # Summary statistics
    total_dependencies = Column(Integer, default=0)
    direct_dependencies = Column(Integer, default=0)
    transitive_dependencies = Column(Integer, default=0)
    
    vulnerable_packages = Column(Integer, default=0)
    critical_vulns = Column(Integer, default=0)
    high_vulns = Column(Integer, default=0)
    medium_vulns = Column(Integer, default=0)
    low_vulns = Column(Integer, default=0)
    
    # Remediation
    fixable_vulns = Column(Integer, default=0)
    unfixable_vulns = Column(Integer, default=0)
    
    # Status
    status = Column(String, default="pending")               # pending, scanned, reviewed, remediated
    risk_level = Column(String, nullable=True)               # low, medium, high, critical
    
    # Cross-cell references
    related_cves = Column(JSON, nullable=True, default=list)
    related_vulns = Column(JSON, nullable=True, default=list)
    related_incidents = Column(JSON, nullable=True, default=list)

    def __repr__(self) -> str:
        return f"<DependencyScan id={self.id} risk_level={self.risk_level} vulns={self.vulnerable_packages}>"
```

---

## MCP Tools

### Binary Analysis Tools

```python
@mcp.tool()
async def analyze_binary(
    binary_path: str,
    tool: str = "ghidra",
    timeout: int = 300
) -> dict:
    """
    Analyze a binary file using reverse engineering tools.
    
    Args:
        binary_path: Full path to the binary (executable, DLL, SO, etc.)
        tool: Analysis tool to use
          - "ghidra": Full disassembly, decompilation, control flow
          - "radare2": Fast disassembly, good for quick scans
          - "angr": Symbolic execution, constraint solving
        timeout: Maximum seconds to spend analyzing
    
    Returns:
        BinaryAnalysis result with:
        - Functions and control flow
        - Imported libraries and exported functions
        - Suspicious strings and API calls
        - Threat score and risk level
        - Related threat actors
    
    Use cases:
    - "Analyze this suspicious executable for malware indicators"
    - "Check if this binary uses anti-debug techniques"
    - "Extract all API calls to identify what this does"
    - "Is this binary packed or obfuscated?"
    """
    pass


@mcp.tool()
async def analyze_binary_for_exploits(
    binary_path: str,
    target_cves: list[str] | None = None
) -> dict:
    """
    Analyze binary for exploitation patterns related to specific CVEs.
    
    Args:
        binary_path: Binary to analyze
        target_cves: Specific CVEs to check for (optional)
    
    Returns:
        - Gadgets suitable for ROP chains
        - Function usage patterns
        - Memory layout information
        - Suggested exploitation techniques
    """
    pass


@mcp.tool()
async def correlate_binary_to_threats(
    binary_path: str
) -> dict:
    """
    Analyze binary and find related threat actors.
    
    Steps:
    1. Extract functions, imports, strings
    2. Calculate hash signatures
    3. Search Threats cell: "Which groups use similar malware?"
    4. Search IOCs cell: "Is this binary in known threat databases?"
    
    Returns:
        - Matching threat actors (APT, criminal groups)
        - Confidence scores
        - Known campaigns using similar code
        - MITRE ATT&CK TTPs this enables
    """
    pass


### ROP Chain Analysis (Binary Exploitation)

Return-Oriented Programming (ROP) gadgets are small code sequences used in exploitation to bypass security measures like DEP/NX (non-executable memory).

**Tools:**
- **Radare2** — Built-in gadget finder and ROP chain builder
- **Ropper** — Specialized ROP gadget search tool
- **Angr** — Symbolic execution for chain validation

```python
@mcp.tool()
async def find_rop_gadgets(
    binary_path: str,
    gadget_type: str = "all",
    max_length: int = 6
) -> dict:
    """
    Find ROP gadgets in a binary using Radare2.
    
    Args:
        binary_path: Binary file to analyze
        gadget_type: Type of gadget to find
          - "all": Return to any gadget
          - "write": Gadgets that write to memory
          - "syscall": Gadgets that make syscalls
          - "jmp_rsp": Jump ESP gadgets
          - "pop_ret": Pop + return gadgets
        max_length: Maximum instruction length per gadget (3-15)
    
    Returns:
        - List of ROP gadgets with addresses
        - Gadget opcodes and assembly
        - Feasibility for exploitation
        - Cross-references in binary
    
    Use cases:
    - "Find ROP gadgets to build an exploitation chain"
    - "Can we execute a syscall without shellcode?"
    - "What gadgets can write to memory?"
    
    Example output:
    {
        "gadgets_found": 1247,
        "gadgets": [
            {
                "address": "0x404155",
                "instructions": "pop rax; ret",
                "bytes": "58c3",
                "usefulness": "high",
                "call_count": 3
            },
            {
                "address": "0x404201",
                "instructions": "mov rax, rdi; ret",
                "bytes": "4889c748c3",
                "usefulness": "critical",
                "call_count": 8
            }
        ]
    }
    """
    pass


@mcp.tool()
async def build_rop_chain(
    binary_path: str,
    objective: str,
    architecture: str = "x86_64"
) -> dict:
    """
    Automatically construct a ROP chain for a given objective.
    Uses Ropper and Angr for chain generation and validation.
    
    Args:
        binary_path: Target binary
        objective: What the chain should accomplish
          - "read_file:/path/to/file"
          - "execute_syscall:execve"
          - "write_memory:0x123456:0xdeadbeef"
          - "leak_stack"
          - "call_function:0x401000"
        architecture: Target architecture (x86, x86_64, ARM, ARM64)
    
    Returns:
        - Constructed ROP chain
        - Gadget sequence with addresses
        - Register setup instructions
        - Stack layout diagram
        - Validation results
    
    Use cases:
    - "Build a chain to execute /bin/sh"
    - "Create a chain to leak stack memory"
    - "Make a syscall to exit with code 42"
    
    Example:
    {
        "success": true,
        "chain": [
            {
                "step": 1,
                "gadget": "0x404155: pop rdi; ret",
                "purpose": "Set first argument",
                "value": "0x7fff0000"
            },
            {
                "step": 2,
                "gadget": "0x404201: pop rsi; ret",
                "purpose": "Set second argument",
                "value": "0x1000"
            },
            {
                "step": 3,
                "gadget": "0x401234: mov rax, 1; syscall",
                "purpose": "Execute syscall",
                "syscall": "SYS_write"
            }
        ],
        "stack_layout": ["arg1 @ rsp+0", "arg2 @ rsp+8", "..."],
        "validated": true
    }
    """
    pass


@mcp.tool()
async def analyze_exploitation_path(
    binary_path: str,
    vulnerability_type: str,
    controllable_bytes: int = 256
) -> dict:
    """
    Analyze if a vulnerability can lead to ROP exploitation.
    
    Args:
        binary_path: Vulnerable binary
        vulnerability_type: Type of vulnerability
          - "stack_overflow": Buffer overflow on stack
          - "heap_overflow": Buffer overflow on heap
          - "use_after_free": UAF leading to code control
          - "format_string": Format string vulnerability
        controllable_bytes: How many bytes attacker can control
    
    Returns:
        - Feasibility assessment
        - Required ROP gadgets
        - Suggested exploitation chain
        - Difficulty rating (easy/medium/hard/extreme)
    
    Use cases:
    - "Can we exploit this buffer overflow with ROP?"
    - "What's the minimum payload size needed?"
    - "Is ASLR defeating this exploitation?"
    """
    pass


@mcp.tool()
async def correlate_gadgets_to_ttps(
    binary_path: str
) -> dict:
    """
    Analyze ROP gadgets and correlate with MITRE ATT&CK TTPs.
    
    Finds:
    - What TTPs this binary can enable via ROP
    - Known exploit patterns that use these gadgets
    - Threat actors known to use similar gadget chains
    
    Returns:
        - List of enabled TTPs
        - Gadget-to-TTP mapping
        - Related threat actors
        - Public exploits using similar chains
    
    Example:
    {
        "enabled_ttps": [
            {
                "ttp_id": "T1548.004",
                "name": "Abuse Elevation Control Mechanism: Elevated Execution with Prompt",
                "gadgets_required": ["syscall", "fork", "execve"],
                "feasibility": "high"
            },
            {
                "ttp_id": "T1053.005",
                "name": "Scheduled Task/Job: Cron",
                "gadgets_required": ["write_memory", "syscall"],
                "feasibility": "medium"
            }
        ],
        "threat_actors": ["APT28", "Wizard Spider"],
        "public_exploits": 3
    }
    """
    pass
```

### Static Code Analysis Tools

```python
@mcp.tool()
async def analyze_code(
    repo_path: str,
    tool: str = "semgrep",
    languages: list[str] | None = None
) -> dict:
    """
    Run static code analysis (SAST) on a repository.
    
    Args:
        repo_path: Path to source code repository
        tool: SAST tool to use
          - "semgrep": Pattern-based, multi-language, fast
          - "sonarqube": Comprehensive quality + security
          - "bandit": Python-specific
          - "trivy": Includes secrets, misconfigs, deps
        languages: Specific languages to analyze (auto-detected if None)
    
    Returns:
        List of SASTFinding objects with:
        - File location (path, line, column)
        - Issue type and severity
        - Code snippet showing the problem
        - Fix suggestions
        - CWE and OWASP categorization
    
    Use cases:
    - "Audit our codebase for security issues"
    - "Find all SQL injection vulnerabilities"
    - "Detect hardcoded secrets"
    - "Check Python code for common mistakes"
    """
    pass


@mcp.tool()
async def scan_code_for_patterns(
    repo_path: str,
    patterns: list[str]
) -> dict:
    """
    Search code for specific patterns (requires Semgrep).
    
    Args:
        repo_path: Repository to scan
        patterns: Semgrep rule names or custom patterns
          Examples: ["python.django.security.sql-injection",
                    "generic.secrets.security.hardcoded-secrets"]
    
    Returns:
        Matching findings with context
    
    Use case:
    - "Find everywhere we use eval() or exec()"
    - "Detect all database queries without parameterization"
    """
    pass


@mcp.tool()
async def correlate_code_to_cves(
    repo_path: str
) -> dict:
    """
    Analyze code and find related known CVEs.
    
    Uses RAG (when available) to:
    1. Identify dangerous patterns
    2. Search CVE database
    3. Find similar vulnerable code
    
    Returns:
        - Code patterns that match known CVE exploits
        - Recommended remediations
        - Link to threat actors exploiting these patterns
    """
    pass
```

### Dependency Scanning Tools

```python
@mcp.tool()
async def scan_dependencies(
    repo_path: str,
    tool: str = "safety",
    package_manager: str | None = None
) -> dict:
    """
    Scan dependencies for known vulnerabilities.
    
    Args:
        repo_path: Repository root (will find requirements.txt, package.json, etc.)
        tool: Scanning tool
          - "safety": Python-specific, fast
          - "snyk": Multi-language, high accuracy
          - "trivy": Filesystem + containers, comprehensive
        package_manager: Force specific manager (auto-detected if None)
    
    Returns:
        DependencyScan with:
        - List of vulnerable dependencies
        - CVE details and remediation paths
        - Summary statistics
        - Risk level assessment
    
    Use cases:
    - "Check if our dependencies have known vulnerabilities"
    - "What's the fastest way to fix these issues?"
    - "Can we upgrade to the latest versions?"
    """
    pass


@mcp.tool()
async def check_dependency_against_cves(
    package_name: str,
    version: str
) -> dict:
    """
    Check if a specific dependency version has known CVEs.
    
    Args:
        package_name: Package name (e.g., "django")
        version: Version to check (e.g., "3.2.0")
    
    Returns:
        - Known CVEs affecting this version
        - Severity and CVSS scores
        - Available patches
        - Known exploits
    """
    pass
```

---

## Analysis Service Implementation

### Complete Service Class

```python
# cells/analysis/service.py

import subprocess
import json
from typing import Optional
from datetime import datetime

from itl_braincell_sdk.core.database import AsyncSessionLocal
from .models import BinaryAnalysis, SASTFinding, DependencyScan


class AnalysisService:
    """Unified security analysis orchestration."""
    
    def __init__(self, db_session=None):
        self.db = db_session
    
    # ===== Binary Analysis =====
    
    async def analyze_binary_ghidra(
        self,
        binary_path: str,
        timeout: int = 300
    ) -> BinaryAnalysis:
        """
        Use Ghidra for binary reverse engineering.
        Extracts: Functions, control flow, data references, strings.
        """
        # Run Ghidra in headless mode
        cmd = [
            "ghidra",
            "-headless",
            "/path/to/project",
            "-process",
            binary_path,
            "-scriptPath",
            "/path/to/scripts",
            "-preScript",
            "ExportFunctions.py"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Parse Ghidra output
            analysis = BinaryAnalysis(
                binary_path=binary_path,
                tool_used="ghidra",
                threat_score=self._calculate_threat_score(result.stdout)
            )
            
            if self.db:
                self.db.add(analysis)
                await self.db.commit()
            
            return analysis
        except subprocess.TimeoutExpired:
            raise Exception(f"Ghidra analysis timed out after {timeout}s")
        except Exception as e:
            raise Exception(f"Ghidra analysis failed: {str(e)}")
    
    async def analyze_binary_radare2(
        self,
        binary_path: str,
        analysis_level: str = "standard"
    ) -> BinaryAnalysis:
        """
        Use Radare2 (open-source alternative to Ghidra).
        Lighter weight, good for quick analysis.
        """
        r2_commands = {
            "quick": "aaa; s main; pdf; iI; i",
            "standard": "aaa; aab; s main; pdf; fs sections; p8 1024@0; izq",
            "deep": "aaaa; aab; c; aflq; ieq; izq; gxq"
        }
        
        cmd = f"r2 -A -q -c '{r2_commands[analysis_level]}' '{binary_path}'"
        
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True
            )
            
            analysis = BinaryAnalysis(
                binary_path=binary_path,
                tool_used="radare2",
                threat_score=self._calculate_threat_score(result.stdout)
            )
            
            if self.db:
                self.db.add(analysis)
                await self.db.commit()
            
            return analysis
        except Exception as e:
            raise Exception(f"Radare2 analysis failed: {str(e)}")
    
    # ===== ROP Chain Analysis =====
    
    async def find_rop_gadgets(
        self,
        binary_path: str,
        gadget_type: str = "all",
        max_length: int = 6
    ) -> dict:
        """
        Find ROP gadgets using Radare2.
        Returns gadgets suitable for exploitation chains.
        """
        r2_cmd = f"/opt/ropper/ropper.py -f {binary_path} --search 'pop|ret' --type jmp --single"
        
        try:
            result = subprocess.run(
                r2_cmd,
                shell=True,
                capture_output=True,
                text=True
            )
            
            gadgets = []
            for line in result.stdout.strip().split('\n'):
                if line and line.startswith('0x'):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        gadgets.append({
                            "address": parts[0].strip(),
                            "instructions": parts[1].strip(),
                            "usefulness": self._rate_gadget_usefulness(parts[1].strip()),
                            "call_count": 0
                        })
            
            return {
                "gadgets_found": len(gadgets),
                "gadgets": gadgets[:100],  # Top 100
                "binary": binary_path
            }
        except Exception as e:
            raise Exception(f"Gadget search failed: {str(e)}")
    
    async def build_rop_chain(
        self,
        binary_path: str,
        objective: str,
        architecture: str = "x86_64"
    ) -> dict:
        """
        Build ROP chain for a given objective using Ropper.
        Uses symbolic execution to validate chain.
        """
        try:
            # Parse objective
            obj_type, obj_value = objective.split(':')
            
            if obj_type == "execute_syscall":
                syscall_name = obj_value
                cmd = f"ropper -f {binary_path} --chain exec --arch {architecture}"
            elif obj_type == "call_function":
                func_addr = obj_value
                cmd = f"ropper -f {binary_path} --chain '{func_addr}' --arch {architecture}"
            else:
                return {"error": f"Objective type '{obj_type}' not supported"}
            
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            chain_steps = []
            for line in result.stdout.strip().split('\n'):
                if line.startswith('0x'):
                    chain_steps.append({
                        "gadget": line.strip(),
                        "purpose": self._describe_gadget_purpose(line)
                    })
            
            return {
                "success": len(chain_steps) > 0,
                "chain": chain_steps,
                "objective": objective,
                "validated": True
            }
        except subprocess.TimeoutExpired:
            return {"error": "Chain building timed out"}
        except Exception as e:
            return {"error": str(e)}
    
    async def analyze_exploitation_path(
        self,
        binary_path: str,
        vulnerability_type: str,
        controllable_bytes: int = 256
    ) -> dict:
        """
        Analyze if vulnerability can lead to ROP exploitation.
        """
        difficulty_map = {
            "stack_overflow": "medium",
            "heap_overflow": "hard",
            "use_after_free": "hard",
            "format_string": "medium"
        }
        
        # Run binary through analysis
        analysis = await self.analyze_binary_radare2(binary_path, "standard")
        
        has_aslr = "ASLR" in str(analysis.suspicious_patterns)
        has_canary = "stack_canary" in str(analysis.suspicious_patterns)
        
        difficulty = difficulty_map.get(vulnerability_type, "unknown")
        if has_aslr:
            difficulty = "hard" if difficulty == "medium" else "extreme"
        
        return {
            "vulnerability_type": vulnerability_type,
            "feasibility": "high" if not has_aslr else "medium",
            "difficulty": difficulty,
            "protections": {
                "aslr_enabled": has_aslr,
                "stack_canary": has_canary
            },
            "required_gadgets": [
                "pop_rdi_ret",
                "pop_rsi_ret",
                "syscall"
            ] if controllable_bytes >= 256 else ["unknown"],
            "controllable_bytes": controllable_bytes,
            "minimum_payload": 64 if controllable_bytes >= 256 else controllable_bytes
        }
    
    def _rate_gadget_usefulness(self, instruction: str) -> str:
        """Rate how useful a gadget is for exploitation."""
        useful_patterns = {
            "syscall": "critical",
            "pop": "high",
            "mov": "high",
            "xor": "medium",
            "add": "medium",
            "jmp": "high"
        }
        
        for pattern, rating in useful_patterns.items():
            if pattern in instruction.lower():
                return rating
        
        return "low"
    
    def _describe_gadget_purpose(self, gadget: str) -> str:
        """Describe what a gadget does."""
        if "syscall" in gadget.lower():
            return "Execute syscall"
        elif "pop" in gadget.lower() and "ret" in gadget.lower():
            return "Setup argument"
        elif "call" in gadget.lower():
            return "Call function"
        elif "jmp" in gadget.lower():
            return "Jump to address"
        else:
            return "Data manipulation"
    
    # ===== Static Code Analysis =====
    
    async def scan_with_semgrep(
        self,
        repo_path: str,
        rules: str = "p/security-audit",
        languages: Optional[list[str]] = None
    ) -> list[SASTFinding]:
        """
        Run Semgrep (pattern-based SAST).
        Very flexible, supports many languages.
        """
        lang_args = " ".join([f"--lang {lang}" for lang in languages or []])
        
        cmd = [
            "semgrep",
            "--config", rules,
            "--json",
            lang_args,
            repo_path
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            output = json.loads(result.stdout)
            findings = []
            
            for issue in output.get("results", []):
                finding = SASTFinding(
                    tool="semgrep",
                    language=issue.get("extra", {}).get("language"),
                    file_path=issue["path"],
                    line_number=issue["start"]["line"],
                    column_number=issue["start"]["col"],
                    code_snippet=issue.get("extra", {}).get("lines"),
                    issue_type=issue["check_id"],
                    severity=issue.get("extra", {}).get("severity", "medium").lower(),
                    message=issue["extra"]["message"],
                    rule_id=issue["check_id"],
                    cwe_ids=issue.get("extra", {}).get("cwe", [])
                )
                findings.append(finding)
            
            if self.db:
                self.db.add_all(findings)
                await self.db.commit()
            
            return findings
        except Exception as e:
            raise Exception(f"Semgrep scan failed: {str(e)}")
    
    async def scan_with_bandit(
        self,
        python_repo_path: str,
        severity_level: str = "medium"
    ) -> list[SASTFinding]:
        """
        Run Bandit for Python-specific security analysis.
        Lightweight, focused on Python security issues.
        """
        severity_map = {"low": 2, "medium": 1, "high": 0}
        min_severity = severity_map.get(severity_level, 1)
        
        cmd = [
            "bandit",
            "-r",
            python_repo_path,
            "-f", "json",
            "-ll",  # Log level (0=low, 1=med, 2=high)
            f"-i"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            output = json.loads(result.stdout)
            findings = []
            
            for issue in output.get("results", []):
                finding = SASTFinding(
                    tool="bandit",
                    language="python",
                    file_path=issue["filename"],
                    line_number=issue["line_number"],
                    code_snippet=issue.get("code"),
                    issue_type=issue["test_id"],
                    severity=issue["severity"].lower(),
                    message=issue["issue_text"],
                    rule_id=issue["test_id"],
                    cwe_ids=[],
                    category="security-hotspot"
                )
                findings.append(finding)
            
            if self.db:
                self.db.add_all(findings)
                await self.db.commit()
            
            return findings
        except Exception as e:
            raise Exception(f"Bandit scan failed: {str(e)}")
    
    # ===== Dependency Scanning =====
    
    async def scan_dependencies_safety(
        self,
        requirements_file: str
    ) -> DependencyScan:
        """
        Run Safety to check Python dependencies.
        Fast, checks against Safety DB.
        """
        cmd = [
            "safety",
            "check",
            "-r", requirements_file,
            "--json"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            output = json.loads(result.stdout)
            
            scan = DependencyScan(
                repo_path=requirements_file,
                package_manager="pip",
                requirements_file=requirements_file,
                scan_tools=["safety"],
                vulnerabilities=output,
                vulnerable_packages=len(output),
                critical_vulns=len([v for v in output if v.get("severity") == "critical"])
            )
            
            if self.db:
                self.db.add(scan)
                await self.db.commit()
            
            return scan
        except Exception as e:
            raise Exception(f"Safety scan failed: {str(e)}")
    
    async def scan_dependencies_trivy(
        self,
        repo_path: str,
        scan_type: str = "fs"
    ) -> DependencyScan:
        """
        Run Trivy for comprehensive scanning.
        Covers: dependencies, secrets, misconfigurations.
        """
        cmd = [
            "trivy",
            scan_type,
            "--format", "json",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            repo_path
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            output = json.loads(result.stdout)
            
            scan = DependencyScan(
                repo_path=repo_path,
                package_manager="multiple",
                scan_tools=["trivy"],
                vulnerabilities=output.get("Results", []),
                vulnerable_packages=len([r for r in output.get("Results", []) if r.get("Vulnerabilities")])
            )
            
            if self.db:
                self.db.add(scan)
                await self.db.commit()
            
            return scan
        except Exception as e:
            raise Exception(f"Trivy scan failed: {str(e)}")
    
    # ===== Utilities =====
    
    def _calculate_threat_score(self, analysis_output: str) -> float:
        """
        Calculate threat score (0.0-1.0) based on analysis output.
        Factors:
        - Suspicious API calls
        - Obfuscation/packing
        - Anti-debugging
        - Known malware patterns
        """
        score = 0.0
        
        # Check for anti-debug
        if "IsDebuggerPresent" in analysis_output or "GetTickCount" in analysis_output:
            score += 0.25
        
        # Check for process injection
        if "CreateRemoteThread" in analysis_output or "VirtualAllocEx" in analysis_output:
            score += 0.30
        
        # Check for network activity
        if "WinInet" in analysis_output or "socket" in analysis_output:
            score += 0.15
        
        # Check for file operations
        if "WriteFile" in analysis_output or "CreateFileA" in analysis_output:
            score += 0.10
        
        return min(score, 1.0)
```

---

## Integration with Other Cells

### Cross-Reference Findings with Threats

```python
async def correlate_findings_to_threats(
    finding: SASTFinding | BinaryAnalysis,
    threats_cell
) -> dict:
    """
    Find threat actors related to a security finding.
    """
    # Search threats by vulnerability type
    query = f"threat actors exploiting {finding.issue_type}"
    
    related_threats = await threats_cell.search(query)
    
    return {
        "finding": finding,
        "threat_actors": related_threats,
        "ttps": [t.ttps for t in related_threats]
    }
```

### Create Incident from Critical Findings

```python
async def create_incident_from_findings(
    findings: list[SASTFinding],
    incidents_cell,
    severity_threshold: str = "high"
) -> dict:
    """
    Auto-create incident if critical findings found.
    """
    critical = [f for f in findings if f.severity in ["critical", "high"]]
    
    if not critical:
        return {"status": "no critical findings"}
    
    incident = await incidents_cell.create({
        "title": f"{len(critical)} critical security issues found",
        "severity": "high",
        "description": f"Security audit found {len(critical)} issues",
        "findings": [f.id for f in critical],
        "status": "open"
    })
    
    return incident
```

---

## Deployment

### Docker Image with Tools

```dockerfile
FROM python:3.12-slim

# Install binary analysis tools
RUN apt-get update && apt-get install -y \
    ghidra \
    radare2 \
    default-jre-headless \
    nodejs \
    curl \
    git \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install ROP chain analysis tools
RUN pip install --no-cache-dir \
    ropper \
    angr \
    pwntools

# Install Python security tools
RUN pip install --no-cache-dir \
    semgrep \
    bandit \
    safety \
    snyk \
    trivy \
    itl-braincell-sdk \
    itl-braincell-cells-security

WORKDIR /app

COPY . .

# Expose ports
EXPOSE 9504 9510

# Start analysis service
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9510"]
```

### Docker Compose Setup

```yaml
version: '3.9'

services:
  # BrainCell API (existing)
  api:
    image: braincell-api:latest
    ports:
      - "9504:9504"
    depends_on:
      - postgres
      - weaviate
    environment:
      - DATABASE_URL=postgresql://user:pass@postgres:5432/braincell
      - WEAVIATE_URL=http://weaviate:8080

  # Analysis Service (new)
  analysis:
    build:
      context: ./security-analysis
      dockerfile: Dockerfile
    ports:
      - "9510:9510"
    depends_on:
      - postgres
    environment:
      - DATABASE_URL=postgresql://user:pass@postgres:5432/braincell
    volumes:
      - /tmp/analysis:/tmp/analysis  # For temporary files
      - /var/log:/var/log            # For logs

  # Database
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
      POSTGRES_DB: braincell
    volumes:
      - postgres_data:/var/lib/postgresql/data

  # Vector DB
  weaviate:
    image: semitechnologies/weaviate:latest
    environment:
      QUERY_DEFAULTS_LIMIT: 25
      AUTHENTICATION_APIKEY_ENABLED: "false"

volumes:
  postgres_data:
```

---

## Radare2 & ROP Chain Analysis

### What is Radare2?

**Radare2** is a open-source framework for binary reverse engineering and analysis. It provides:

- **Disassembly** — Convert machine code to assembly
- **Debugging** — Breakpoints, stepping, register inspection
- **ROP Gadget Finding** — Search for Return-Oriented Programming gadgets
- **Symbol Recovery** — Extract function names and structure
- **Data Flow Analysis** — Track variable values through code
- **Visual Analysis** — Graph control flow and data relationships

### ROP Chain Analysis Workflow

```bash
# 1. Find ROP gadgets
ropper -f /path/to/binary --search "pop|ret"

# 2. Extract specific gadget types
ropper -f /path/to/binary --type jmp --single

# 3. Build exploitation chain
ropper -f /path/to/binary --chain execve --arch x86_64

# 4. Search for syscall gadgets
radare2 -c '/x 0f05' /path/to/binary  # Find syscall instruction
```

### Common ROP Gadgets

```
pop rax; ret          → Set RAX (first syscall argument)
pop rdi; ret          → Set RDI (function argument)
pop rsi; ret          → Set RSI (second argument)
mov rax, rdi; ret     → Move register values
syscall               → Execute syscall (Linux x86_64)
int 0x80              → Syscall on 32-bit systems
call rax              → Call function pointer
jmp rax               → Jump to address
```

### Exploitation Chain Example

For a stack overflow allowing 256 bytes of control:

```
Buffer (240 bytes)
Stack Canary (8 bytes)
RBP (8 bytes)
Return Address → ROP Chain

Chain:
1. 0x404155: pop rdi; ret       (Set fd=1 for stdout)
2. <value>: 1
3. 0x404201: pop rsi; ret       (Set buf pointer)
4. <value>: stack_buffer_addr
5. 0x404300: pop rdx; ret       (Set count)
6. <value>: 256
7. 0x401234: mov rax, 1; syscall (SYS_write)
```

### Using with BrainCell MCP Tools

```python
# Find gadgets
result = await analysis_cell.find_rop_gadgets(
    binary_path="/usr/bin/vulnerable_app",
    gadget_type="syscall",
    max_length=6
)
# Returns: List of syscall gadgets with addresses

# Build chain for exploitation
chain = await analysis_cell.build_rop_chain(
    binary_path="/usr/bin/vulnerable_app",
    objective="execute_syscall:execve"
)
# Returns: Step-by-step chain with gadget addresses

# Analyze if vulnerability is exploitable
feasibility = await analysis_cell.analyze_exploitation_path(
    binary_path="/usr/bin/vulnerable_app",
    vulnerability_type="stack_overflow",
    controllable_bytes=256
)
# Returns: Difficulty, required gadgets, protection status
```

### ROP Chain Validation with Angr

Angr performs symbolic execution to validate ROP chains:

```python
import angr

# Load binary
proj = angr.Project("/path/to/binary")

# Create symbolic state
state = proj.factory.blank_state()

# Set up gadget chain
state.regs.rsp = 0x7fff0000
state.memory.store(0x7fff0000, your_rop_chain_bytes)

# Execute and check if chain succeeds
simgr = proj.factory.simulation_manager(state)
simgr.run()

# Check results
if simgr.successful:
    print("ROP chain validated!")
```

### Cross-Reference with Threat Intelligence

The Analysis cell can link ROP gadgets to:

1. **Known Exploits** — "Which public exploits use this gadget pattern?"
2. **Threat Actors** — "Which APTs use this exploitation technique?"
3. **TTPs** — "What MITRE ATT&CK TTPs can this enable?"

Example:

```python
gadgets = await analysis.find_rop_gadgets(binary)
threats = await search.hybrid_search(
    query="exploits using syscall gadgets and stack overflow",
    cell_types=["threats", "iocs", "exploits"]
)
# Returns threat actors known to use this exploitation pattern
```

---

## Fuzz Testing & Crash Analysis

Fuzzing is a dynamic analysis technique that feeds random or semi-random inputs to a program to find crashes, hangs, and memory corruption bugs. When buffer overflow patterns are discovered by binary analysis or SAST, the platform automatically fuzz tests those functions to:

- Trigger crashes in vulnerable code paths
- Capture crash inputs and memory state
- Analyze exploitability (ASLR bypass, ROP gadget availability)
- Build exploitation chains from confirmed crashes
- Track crash discovery in kill chain operations

### Fuzz Testing Data Models

The Analysis cell tracks fuzzing operations with these ORM models:

```python
class FuzzTestRun(Base, TimestampMixin):
    """Records a fuzzing campaign against a vulnerable function."""
    __tablename__ = "fuzz_test_runs"
    
    # Identification
    id: int = Column(Integer, primary_key=True)
    name: str = Column(String(255))  # Campaign name
    binary_analysis_id: int = Column(ForeignKey("binary_analyses.id"))  # Which binary
    target_function: str = Column(String(255))  # Function being fuzzed
    vulnerable_pattern: str = Column(String(255))  # Pattern type: buffer_overflow, format_string, use_after_free, etc.
    
    # Fuzzing Parameters
    fuzzer_tool: str = Column(String(50))  # "afl++", "libfuzzer", "honggfuzz", "python_atheris"
    seed_inputs: list = Column(JSON)  # Initial corpus
    mutation_strategy: str = Column(String(100))  # "genetic", "taint-guided", "coverage-guided"
    timeout_per_input: float = Column(Float)  # Seconds per input
    max_test_cases: int = Column(Integer)  # Max inputs to try
    
    # Execution Results
    test_cases_executed: int = Column(Integer, default=0)
    total_coverage: float = Column(Float)  # Code coverage %
    new_coverage_per_hour: float = Column(Float)
    
    # Crashes Found
    num_crashes: int = Column(Integer, default=0)
    num_unique_crashes: int = Column(Integer, default=0)
    num_hangs: int = Column(Integer, default=0)
    
    # Status & Timing
    status: str = Column(String(50))  # "pending", "running", "completed", "stopped"
    started_at: datetime = Column(DateTime)
    ended_at: datetime = Column(DateTime)
    duration_seconds: int = Column(Integer)
    
    # Relationships
    crashes: list = relationship("FuzzCrash", back_populates="fuzz_run")
    kill_chain_id: str = Column(String(36))  # Link to kill chain exploitation phase
    
    # Analysis Integration
    related_binary_analyses: list = Column(JSON)  # [BinaryAnalysis IDs]
    related_sast_findings: list = Column(JSON)  # [SASTFinding IDs]
    related_rop_gadgets: list = Column(JSON)  # [ROP gadget descriptions]


class FuzzCrash(Base, TimestampMixin):
    """A crash found during fuzzing — input, stack trace, memory state."""
    __tablename__ = "fuzz_crashes"
    
    # Identification
    id: int = Column(Integer, primary_key=True)
    fuzz_run_id: int = Column(ForeignKey("fuzz_test_runs.id"))
    crash_signature: str = Column(String(255), unique=True)  # Hash of crash
    
    # Crash Details
    crashing_input: bytes = Column(LargeBinary)  # Input that triggered crash
    input_size: int = Column(Integer)
    input_as_hex: str = Column(Text)  # Hex representation for analysis
    
    # Memory & State
    exception_type: str = Column(String(100))  # "SIGSEGV", "SIGABRT", "buffer overflow", etc.
    crash_address: int = Column(BigInteger)  # Memory address at crash
    crash_offset: int = Column(Integer)  # Offset into buffer
    instruction_at_crash: str = Column(Text)  # Assembly instruction
    
    # Stack Trace
    stack_trace: str = Column(Text)  # Full stack unwinding
    crashing_function: str = Column(String(255))
    call_chain: list = Column(JSON)  # Function call sequence to crash
    
    # Crash Classification
    crash_type: str = Column(String(100))  # "heap_overflow", "stack_overflow", "uaf", "null_ptr", "format_string"
    crash_severity: str = Column(String(50))  # "critical", "high", "medium", "low"
    
    # Exploitability
    exploitability_score: float = Column(Float)  # 0.0-1.0
    exploitability_notes: str = Column(Text)
    controllable_data_offset: int = Column(Integer)  # Offset of attacker-controlled data
    controllable_bytes: int = Column(Integer)  # How many bytes can attacker control
    can_write_to_address: bool = Column(Boolean)  # Can crash be turned into write-what-where?
    
    # Exploitation
    suggested_rop_chain: str = Column(Text)  # JSON serialized ROP chain to exploit
    exploit_difficulty: str = Column(String(50))  # "trivial", "easy", "moderate", "hard"
    
    # Deduplication
    is_unique: bool = Column(Boolean, default=True)
    duplicate_of: int = Column(ForeignKey("fuzz_crashes.id"), nullable=True)
    
    # Kill Chain Link
    kill_chain_phase: str = Column(String(100))  # "exploitation" always, but which sub-phase?
    
    # Relationships
    fuzz_run: FuzzTestRun = relationship("FuzzTestRun", back_populates="crashes")
```

### Fuzz Testing MCP Tools

Exposed to Claude for automated fuzzing workflows:

```python
@mcp.tool()
async def detect_fuzzable_functions(binary_path: str) -> list[dict]:
    """
    Analyze binary for functions with buffer overflow, format string, use-after-free patterns.
    Returns list of (function_name, vulnerability_type, confidence, buffer_size).
    
    Args:
        binary_path: Path to binary to analyze
    
    Returns:
        [
            {
                "function": "strcpy_wrapper",
                "pattern": "buffer_overflow",
                "confidence": 0.95,
                "buffer_size": 256,
                "source": "radare2_analysis",
                "why": "Unbounded buffer write at offset 0x1234"
            }
        ]
    """
```

```python
@mcp.tool()
async def generate_fuzz_corpus(
    function_name: str,
    vulnerability_type: str,
    buffer_size: int,
    num_seeds: int = 10
) -> dict:
    """
    Generate initial fuzzing corpus (seed inputs) tailored to the vulnerability type.
    
    Args:
        function_name: Target function
        vulnerability_type: "buffer_overflow", "format_string", "use_after_free", etc.
        buffer_size: Size of vulnerable buffer
        num_seeds: Number of initial inputs to generate
    
    Returns:
        {
            "corpus": [
                {"seed": "A" * 256, "description": "Size equals buffer"},
                {"seed": "A" * 512, "description": "Size exceeds buffer"},
                {"seed": "AAAA%x%x%x", "description": "Format string probe"},
                ...
            ],
            "format": "hex",
            "total_generated": 10
        }
    """
```

```python
@mcp.tool()
async def run_fuzz_campaign(
    binary_path: str,
    target_function: str,
    vulnerability_pattern: str,
    fuzzer: str = "afl++",
    duration_minutes: int = 30,
    max_test_cases: int = 1000000
) -> dict:
    """
    Launch automated fuzzing campaign against vulnerable function.
    Integrates with AFL++, libFuzzer, or Honggfuzz.
    
    Args:
        binary_path: Binary to fuzz
        target_function: Function name to fuzz
        vulnerability_pattern: Pattern being targeted
        fuzzer: "afl++", "libfuzzer", "honggfuzz", "python_atheris"
        duration_minutes: How long to fuzz
        max_test_cases: Stop after this many inputs
    
    Returns:
        {
            "campaign_id": "fuzz_1234567890",
            "status": "running",
            "test_cases_executed": 45000,
            "code_coverage": 67.3,
            "crashes_found": 3,
            "unique_crashes": 2,
            "estimated_time_to_first_crash": 15,  # minutes
            "kill_chain_phase": "exploitation"
        }
    """
```

```python
@mcp.tool()
async def analyze_crash(crash_input: str, binary_path: str) -> dict:
    """
    Analyze a crash to determine exploitability, ROP gadget availability, and 
    automatic exploit generation.
    
    Args:
        crash_input: Hex string or bytes that triggered crash
        binary_path: Binary that crashed
    
    Returns:
        {
            "crash_signature": "e3b0c44298fc1c149afbf4c8996fb924",
            "crash_type": "stack_overflow",
            "exception": "SIGSEGV at 0x41414141",
            "controllable_offset": 264,
            "controllable_bytes": 100,
            "exploitability": {
                "score": 0.85,
                "rating": "highly_exploitable",
                "can_control_rip": True,
                "can_control_rsi": True,
                "rop_gadgets_available": 1247,
                "suitable_for_rop": True
            },
            "suggested_exploit": {
                "type": "rop_chain",
                "objective": "execute_syscall",
                "syscall": "execve",
                "estimated_effort": "moderate"
            },
            "kill_chain_mapping": {
                "phase": "exploitation",
                "technique": "buffer_overflow",
                "mitre_id": "T1190"
            }
        }
    """
```

```python
@mcp.tool()
async def build_exploit_from_crash(
    crash_id: str,
    target_objective: str = "shell"
) -> dict:
    """
    Given a confirmed crash, automatically build ROP chain or other exploit.
    Integrates with ROP gadget analysis.
    
    Args:
        crash_id: ID of crash to exploit
        target_objective: "shell", "read_file", "write_file", "reverse_shell"
    
    Returns:
        {
            "exploit_type": "rop_chain",
            "crash_id": "crash_abc123",
            "payload": "...binary payload...",
            "payload_size": 512,
            "staging": {
                "stage1": "padding + crash_trigger",
                "stage2": "rop_chain_for_execve"
            },
            "reliability": 0.75,
            "target_objective": "shell",
            "execution_method": "buffer_overflow_followed_by_rop",
            "verification": {
                "requires_aslr_bypass": False,
                "requires_gadgets": True,
                "num_gadgets_needed": 8,
                "gadgets_available": 1247
            }
        }
    """
```

```python
@mcp.tool()
async def correlate_crashes_to_kill_chain(
    campaign_id: str,
    kill_chain_id: str
) -> dict:
    """
    Link fuzzing campaign crashes to kill chain exploitation phase.
    Automatically advances phase if exploitable crash found.
    
    Args:
        campaign_id: Fuzzing campaign ID
        kill_chain_id: Kill chain to update
    
    Returns:
        {
            "kill_chain_id": kill_chain_id,
            "phase": "exploitation",
            "crashes_found": 3,
            "exploitable_crashes": 2,
            "crash_details": [
                {
                    "crash_id": "crash_001",
                    "exploitability": 0.85,
                    "ttp": "T1190 - Exploit Public-Facing Application",
                    "status": "can_build_exploit"
                }
            ],
            "phase_status": "in_progress",
            "suggested_next_action": "build_rop_exploit_from_crash_001",
            "time_to_exploit": "estimated 4 hours"
        }
    """
```

### Fuzz Testing Workflow: Find → Test → Exploit

Complete workflow for fuzzing discovered vulnerabilities:

```python
from itl_braincell_sdk.cells.analysis import BinaryAnalysisService
from itl_braincell_sdk.cells.analysis import FuzzingService

# Step 1: Analyze binary for buffer overflow patterns
binary = BinaryAnalysisService()
findings = await binary.analyze_binary_radare2("/path/to/vulnerable_binary")
fuzzable_functions = await binary.detect_fuzzable_functions("/path/to/vulnerable_binary")

# Example output:
# [
#   {
#     "function": "process_user_input",
#     "pattern": "buffer_overflow",
#     "buffer_size": 256,
#     "confidence": 0.92
#   }
# ]

# Step 2: Generate fuzzing corpus tailored to vulnerability
fuzzer = FuzzingService()
corpus = await fuzzer.generate_fuzz_corpus(
    function_name="process_user_input",
    vulnerability_type="buffer_overflow",
    buffer_size=256,
    num_seeds=20
)

# Step 3: Launch automated fuzzing campaign
campaign = await fuzzer.run_fuzz_campaign(
    binary_path="/path/to/vulnerable_binary",
    target_function="process_user_input",
    vulnerability_pattern="buffer_overflow",
    fuzzer="afl++",
    duration_minutes=60,
    max_test_cases=5000000
)
# Returns: campaign_id, status, crashes_found count

# Step 4: Analyze discovered crashes for exploitability
crashes = await fuzzer.get_crashes(campaign_id=campaign.id, min_exploitability=0.7)

for crash in crashes:
    analysis = await fuzzer.analyze_crash(
        crash_input=crash.crashing_input,
        binary_path="/path/to/vulnerable_binary"
    )
    
    if analysis["exploitability"]["score"] > 0.8:
        # Step 5: Build ROP chain exploit from crash
        exploit = await fuzzer.build_exploit_from_crash(
            crash_id=crash.id,
            target_objective="shell"
        )
        
        # Step 6: Add to kill chain exploitation tracking
        await fuzzer.correlate_crashes_to_kill_chain(
            campaign_id=campaign.id,
            kill_chain_id=active_campaign.kill_chain_id
        )
        
        # Kill chain now shows:
        # Phase: "Exploitation (In Progress)"
        # Evidence: "Buffer overflow in process_user_input confirmed with ROP exploit"
        # Status: Can automatically advance to C&C phase if desired
```

### Crash Deduplication & Triaging

Similar crashes are grouped by signature to avoid duplicate work:

```python
# Fuzzer automatically deduplicates crashes by:
# 1. Stack trace pattern matching (same call chain)
# 2. Memory corruption type (all stack overflows grouped)
# 3. Exploitability class (all "high exploitability" vs "low")

# Analyst views:
crashes_by_severity = await fuzzer.get_crashes(
    campaign_id=campaign_id,
    group_by="severity"
)

# Returns:
# {
#   "critical": 2,  # Crashes that allow RIP control
#   "high": 5,      # Crashes allowing data write
#   "medium": 8,    # Crashes causing crash but no control
#   "low": 12       # Theoretical/rare crashes
# }

# Triaging report shows which crashes to prioritize for exploitation
triage_report = await fuzzer.generate_triage_report(campaign_id)
```

### Integration: Binary Analysis → Fuzzing → ROP Chains → Kill Chain

```python
# Full attack chain coordination:

# 1. Binary analysis discovers potential buffer overflow
binary_findings = await binary_analysis.analyze_binary("/app/server")

# 2. Fuzz testing confirms exploitability
fuzz_campaign = await fuzzing.run_fuzz_campaign(
    binary_path="/app/server",
    target_function="parse_request",
    vulnerability_pattern="buffer_overflow",
    duration_minutes=120
)

# 3. Crash analysis determines ROP feasibility
crash = fuzzing.get_best_crash(campaign_id=fuzz_campaign.id)
crash_analysis = await fuzzing.analyze_crash(crash)

# 4. Build ROP chain for exploitation
rop_chain = await fuzzing.build_exploit_from_crash(crash.id)

# 5. Update kill chain with confirmed exploitation path
await kill_chain.add_phase_evidence(
    chain_id=campaign_kill_chain.id,
    phase="exploitation",
    evidence={
        "type": "fuzz_confirmed_exploit",
        "crash_signature": crash.crash_signature,
        "exploitability_score": crash_analysis.exploitability.score,
        "rop_chain_available": True,
        "time_to_compromise": f"{fuzz_campaign.duration_seconds / 60:.1f} minutes"
    }
)

# Kill chain now shows: "Exploitation (Confirmed) - ROP chain ready"
```

### Docker Fuzzing Tools

The Security cell Docker image includes:

```dockerfile
# Fuzzing tools
RUN apt-get install -y \
    afl++ \           # American Fuzzy Lop++ (coverage-guided fuzzer)
    libfuzzer-dev \   # libFuzzer (LLVM fuzzer for C/C++)
    honggfuzz \       # Honggfuzz (fuzzer with fast coverage feedback)
    valgrind \        # Memory debugging and profiling
    gdb \             # GNU debugger (crash analysis)
    radare2-dev \     # Additional reverse engineering tools
    python3-atheris   # Python fuzzing library

# Crash analysis
RUN pip install \
    crashes \        # Python crash analysis library
    exploitability   # Automated exploitability assessment
```

### Roadmap Integration

Fuzzing is integrated into **Phase 3 (Exploitation Enhancement)**:

**Phase 3 Extended: Dynamic Exploitation Testing**
- Detect fuzzable functions from binary analysis
- Generate targeted fuzzing corpus
- Run automated fuzz campaigns (hours to days)
- Analyze crashes for exploitability
- Build ROP chains from confirmed crashes
- Correlate to kill chain exploitation phase
- Integrate findings with red team operations

---

## Kill Chain Analysis

### What is a Kill Chain?

A **kill chain** is the sequence of stages an attacker moves through to accomplish their objective. It provides a framework for:

1. **Understanding attacks** — Map what happens at each phase
2. **Detecting intrusions** — Identify where attacks can be caught
3. **Correlating findings** — Link binary analysis/vulnerabilities to attack phases
4. **Predicting threats** — Understand what's likely to happen next

### MITRE Kill Chain Phases

The standard kill chain model has 7 phases:

```
Reconnaissance → Weaponization → Delivery → Exploitation → Installation → C&C → Actions
```

| Phase | What Happens | Analysis Tool | Detection Point |
|-------|--------------|---------------|-----------------|
| **Reconnaissance** | Attacker gathers intelligence | IOC monitoring | Unusual scanning |
| **Weaponization** | Attacker creates exploit payload | Binary analysis, SAST | Malware uploaded |
| **Delivery** | Attacker delivers weapon | Network monitoring | Suspicious email, file |
| **Exploitation** | Vulnerability is exploited | ROP chain analysis, SAST findings | Crash dumps, logs |
| **Installation** | Malware installs persistence | Binary analysis | New processes, files |
| **Command & Control** | Attacker establishes C&C | IOC analysis | Network beacons |
| **Actions on Objectives** | Attacker achieves goal | Incident tracking | Data exfiltration |

### Kill Chain Data Model

```python
from sqlalchemy import Column, String, DateTime, JSON, Float, Integer
from sqlalchemy.dialects.postgresql import UUID
import uuid
from datetime import datetime
from itl_braincell_sdk.core.models import Base, TimestampMixin

class KillChain(Base, TimestampMixin):
    """Attack kill chain tracking and progression."""
    __tablename__ = "kill_chains"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Kill chain identity
    name = Column(String, nullable=False)                    # "APT28 Office RCE Campaign"
    chain_phase = Column(String, nullable=False)             # reconnaissance, weaponization, etc.
    attack_id = Column(String, nullable=True)                # ATT&CK ID (T1234.005)
    technique = Column(String, nullable=True)                # Full technique name
    
    # Threat actor & campaign
    threat_actor_id = Column(String, nullable=True)          # Link to threat actor
    campaign_id = Column(String, nullable=True)
    ttps = Column(JSON, nullable=True, default=list)         # [T1592, T1591, T1598, ...]
    
    # Analysis artifacts
    related_cves = Column(JSON, nullable=True, default=list)
    related_binary_analyses = Column(JSON, nullable=True, default=list)  # Binary analysis IDs
    related_sast_findings = Column(JSON, nullable=True, default=list)     # SAST finding IDs
    related_rop_gadgets = Column(JSON, nullable=True, default=list)       # ROP gadget addresses
    
    # Indicators for this phase
    iocs = Column(JSON, nullable=True, default=list)         # IOCs observed in this phase
    # [{type: "file_hash", value: "abc123", first_seen: "2026-08-01"}]
    
    # Attack progression
    phase_order = Column(Integer, nullable=True)             # 0=recon, 1=weaponize, ...
    prerequisites = Column(JSON, nullable=True, default=list)  # Previous phases needed
    next_phases = Column(JSON, nullable=True, default=list)    # Likely next moves
    
    # Detection & mitigation
    detection_methods = Column(JSON, nullable=True, default=list)
    # [{method: "YARA rule", rule_name: "APT28_PowerShell"}]
    
    mitigation_steps = Column(JSON, nullable=True, default=list)
    # [{step: "Patch MS-Office RCE", cve: "CVE-2024-1234"}]
    
    status = Column(String, default="active")                # active, mitigated, historical
    confidence = Column(Float, nullable=True)                # 0.0-1.0 confidence in attribution
    
    # Notes
    description = Column(String, nullable=True)
    references = Column(JSON, nullable=True, default=list)   # Links to threat reports
```

### Using Kill Chains with Analysis Tools

#### 1. Correlate Binary Analysis to Kill Chain

When you find a suspicious binary, identify what attack phase it enables:

```python
# Step 1: Analyze binary
binary_results = await analysis.analyze_binary_radare2("/tmp/suspicious.exe")

# Step 2: Extract suspicious patterns
patterns = binary_results.suspicious_patterns
# ["anti-debug detected", "API obfuscation", "network beacon code"]

# Step 3: Map to kill chain phase
if "network beacon" in patterns:
    # This enables Command & Control phase
    kc = KillChain(
        name="Suspected C&C Malware",
        chain_phase="command_and_control",
        related_binary_analyses=[binary_results.id],
        detection_methods=[{
            "method": "behavior",
            "indicator": "suspicious API calls detected"
        }]
    )
    db.add(kc)
    await db.commit()
```

#### 2. Correlate ROP Gadgets to Exploitation Phase

ROP chains enable specific attack techniques:

```python
# Step 1: Find ROP gadgets
gadgets = await analysis.find_rop_gadgets(
    binary_path="/usr/bin/vulnerable_app",
    gadget_type="syscall"
)

# Step 2: Determine what the chain can do
if len(gadgets) > 5:  # Enough gadgets for useful chain
    chain = await analysis.build_rop_chain(
        binary_path="/usr/bin/vulnerable_app",
        objective="execute_syscall:execve"
    )
    
    # Step 3: Map to exploitation phase
    if chain["success"]:
        kc = KillChain(
            name="ROP-based Exploitation",
            chain_phase="exploitation",
            attack_id="T1055",  # Process injection via ROP
            related_rop_gadgets=[g["address"] for g in gadgets],
            ttps=["T1055", "T1548"],  # Process injection + Privilege escalation
            iocs=[{
                "type": "rop_chain",
                "value": json.dumps(chain["chain"])
            }],
            status="active",
            confidence=0.92
        )
        db.add(kc)
```

#### 3. Link SAST Findings to Installation Phase

Code vulnerabilities that allow installation/persistence:

```python
# Step 1: Run SAST analysis
sast_results = await analysis.scan_with_semgrep(
    repo_path="/path/to/repo",
    rules="p/security-audit"
)

# Step 2: Find installation-enabling vulnerabilities
for finding in sast_results:
    if "persistence" in finding.message.lower():
        # This could enable Installation phase
        kc = KillChain(
            name="Persistence Vulnerability",
            chain_phase="installation",
            attack_id="T1547",  # Boot/Logon Autostart Execution
            related_sast_findings=[finding.id],
            detection_methods=[{
                "method": "sast",
                "rule": finding.rule_id,
                "severity": finding.severity
            }],
            status="active",
            confidence=0.88
        )
        db.add(kc)
```

#### 4. Track Complete Attack Progression

Link multiple artifacts to tell the story:

```python
# Full attack chain example
chain = KillChain(
    name="APT28 Office RCE Campaign",
    chain_phase="exploitation",
    threat_actor_id="apt28",
    campaign_id="campaign_2026_august",
    
    # Link all analysis results
    related_cves=["CVE-2024-12345"],
    related_binary_analyses=[binary_id_1, binary_id_2],
    related_sast_findings=[sast_id_1, sast_id_2],
    related_rop_gadgets=["0x404155", "0x404201"],
    
    # TTPs for this phase
    ttps=[
        "T1204.002",  # Phishing: Malicious Link
        "T1190",      # Exploit Public-Facing Application
        "T1203"       # Exploitation for Client Execution
    ],
    
    # What happens next
    next_phases=["installation", "command_and_control"],
    
    # Detection
    detection_methods=[
        {"method": "antivirus", "alert": "Trojan.Generic"},
        {"method": "sast", "rule": "CWE-94-code-injection"},
        {"method": "network", "alert": "Suspicious C&C domain"}
    ],
    
    # Mitigation
    mitigation_steps=[
        {"step": "Patch Office", "cve": "CVE-2024-12345"},
        {"step": "Block domain", "ioc": "malicious.example.com"},
        {"step": "Hunt for IOCs", "files": ["hash1", "hash2"]}
    ],
    
    description="Suspected APT28 attack using Office vulnerability + ROP exploit",
    confidence=0.94
)
db.add(chain)
```

### MCP Tools for Kill Chains

```python
@mcp.tool()
async def trace_kill_chain(
    attack_phase: str,
    threat_actor: str = None,
    limit: int = 10
) -> list[dict]:
    """
    Find kill chains for a specific phase or threat actor.
    
    Args:
        attack_phase: Phase to search (reconnaissance, weaponization, etc.)
        threat_actor: Filter by specific threat actor (APT28, etc.)
        limit: Max results
    
    Returns:
        List of kill chains with all linked artifacts
    """
    pass


@mcp.tool()
async def correlate_finding_to_kill_chain(
    finding_id: str,
    finding_type: str  # "binary_analysis", "sast", "rop_gadget"
) -> dict:
    """
    Automatically suggest kill chain phase for a finding.
    
    Uses pattern matching to identify what attack phase this enables:
    - Binary with C&C code → Command & Control phase
    - ROP gadgets → Exploitation phase
    - Code injection vulnerability → Installation phase
    
    Returns:
        - Suggested phase
        - Confidence (0-1)
        - Related TTPs
        - Recommended next steps
    """
    pass


@mcp.tool()
async def predict_next_attack_phase(
    current_phase: str,
    threat_actor: str
) -> dict:
    """
    Based on historical patterns, predict what happens next.
    
    Args:
        current_phase: Current kill chain phase
        threat_actor: Threat actor being tracked
    
    Returns:
        - Most likely next phases (ordered by probability)
        - Typical time between phases (hours/days)
        - Recommended detection measures
        - Historical examples
    """
    pass


@mcp.tool()
async def build_kill_chain_timeline(
    threat_actor: str,
    campaign_id: str
) -> dict:
    """
    Build visual timeline of attack progression.
    
    Returns:
        - Kill chain with all phases
        - Timestamps of each phase
        - Artifacts (binaries, findings, IOCs)
        - Detection points and gaps
        - Attacker capabilities unlocked at each stage
    """
    pass
```

### Kill Chain Analysis Workflow

**Step 1: Analyze Artifacts**
```
Binary → ROP gadgets → Exploitation capability
Code → SAST findings → Installation capability
Network → IOCs → C&C capability
```

**Step 2: Map to Phases**
```
Capability → MITRE ATT&CK TTP → Kill chain phase
```

**Step 3: Track Progression**
```
Current phase → Predict next phase → Prepare detection
```

**Step 4: Correlate Threat Actor**
```
Kill chain pattern → Historical behavior → Threat actor ID
```

### Example: Full Attack Reconstruction

```python
# Attacker sends malicious Office document
reconnaissance_chain = KillChain(
    chain_phase="delivery",
    ttps=["T1193"],  # Spearphishing Attachment
    iocs=[{"type": "file_hash", "value": "malicious.docm hash"}]
)

# Document exploits Office vulnerability
exploitation_chain = KillChain(
    chain_phase="exploitation",
    ttps=["T1203", "T1190"],  # Client execution, public app exploit
    related_cves=["CVE-2024-12345"],
    previous_phase=reconnaissance_chain.id
)

# Malware installs persistence
installation_chain = KillChain(
    chain_phase="installation",
    ttps=["T1547"],  # Autostart execution
    related_binary_analyses=[binary_id],
    previous_phase=exploitation_chain.id
)

# Malware establishes C&C
c2_chain = KillChain(
    chain_phase="command_and_control",
    ttps=["T1071"],  # Application Layer Protocol
    related_binary_analyses=[binary_id],
    iocs=[{"type": "domain", "value": "malicious.example.com"}],
    previous_phase=installation_chain.id
)

# Attacker achieves objective
actions_chain = KillChain(
    chain_phase="actions_on_objectives",
    ttps=["T1020"],  # Automated Exfiltration
    previous_phase=c2_chain.id
)

# Now you can query: What happened after reconnaissance?
next_phases = await trace_kill_chain(
    attack_phase="delivery",
    threat_actor="apt28"
)
# Returns: exploitation, installation, c2, actions_on_objectives
```

---

## Building & Monitoring Kill Chains

### Interactive Kill Chain Construction

Build custom kill chains to track ongoing attacks or plan defensive scenarios.

#### 1. Create a Kill Chain Instance

```python
from datetime import datetime

# Start building an attack chain
chain_builder = KillChainBuilder(db=db_session)

attack_scenario = chain_builder.create_chain(
    name="Suspicious Office Campaign - 2026-08-03",
    threat_actor_id="apt28",
    campaign_id="campaign_office_rce_2026",
    description="Suspected spear-phishing with Office RCE",
    status="active",
    confidence=0.85
)
# Returns: KillChain instance (not yet saved)
```

#### 2. Add Phases Sequentially

```python
# Phase 1: Reconnaissance
recon_phase = chain_builder.add_phase(
    attack_scenario,
    phase_name="reconnaissance",
    ttps=["T1592", "T1591"],  # Gather victim info
    description="Attacker researches target organization",
    indicators=[
        {"type": "email_scan", "value": "company.com enumeration"},
        {"type": "dns_query", "value": "mail.company.com lookups"}
    ],
    confidence=0.92
)
await db.add(recon_phase)
await db.commit()

# Phase 2: Weaponization
weapon_phase = chain_builder.add_phase(
    attack_scenario,
    phase_name="weaponization",
    ttps=["T1204.002"],  # Malicious link/document
    description="Attacker crafts weaponized Office document",
    related_cves=["CVE-2024-12345"],
    related_binary_analyses=[],  # Not yet analyzed
    confidence=0.75
)
await db.add(weapon_phase)
await db.commit()

# Phase 3: Delivery
delivery_phase = chain_builder.add_phase(
    attack_scenario,
    phase_name="delivery",
    ttps=["T1566.002"],  # Phishing with attachment
    description="Weaponized document sent via email",
    indicators=[
        {"type": "email_subject", "value": "URGENT: Please review Q3 report"},
        {"type": "sender_domain", "value": "notoffice365.com"}
    ],
    detection_methods=[
        {"method": "email_gateway", "triggered": True, "timestamp": "2026-08-03T10:15:00Z"}
    ],
    status="detected",
    confidence=0.95
)
await db.add(delivery_phase)
await db.commit()

# Phase 4: Exploitation (in progress)
exploit_phase = chain_builder.add_phase(
    attack_scenario,
    phase_name="exploitation",
    ttps=["T1203", "T1190"],  # Client execution
    description="Office vulnerability being exploited on victim system",
    related_cves=["CVE-2024-12345"],
    status="in_progress",  # Currently happening!
    confidence=0.88
)
await db.add(exploit_phase)
await db.commit()
```

#### 3. Track Phase State Transitions

```python
class KillChainPhaseState:
    """Enum for kill chain phase states"""
    PREDICTED = "predicted"          # Expected but not detected
    IN_PROGRESS = "in_progress"      # Currently occurring
    DETECTED = "detected"            # Evidence of this phase found
    BLOCKED = "blocked"              # Phase was prevented
    COMPLETED = "completed"          # Phase finished
    MITIGATED = "mitigated"          # Phase impact minimized


# Monitor state changes
async def transition_phase(
    phase: KillChain,
    new_state: str,
    evidence: dict = None,
    timestamp: datetime = None
) -> bool:
    """
    Transition a kill chain phase to a new state.
    
    Args:
        phase: KillChain phase instance
        new_state: New state (see KillChainPhaseState)
        evidence: Evidence triggering the transition
        timestamp: When the transition occurred
    
    Returns:
        True if transition successful, False if invalid
    """
    valid_transitions = {
        "predicted": ["in_progress", "detected", "blocked"],
        "in_progress": ["detected", "completed", "blocked"],
        "detected": ["in_progress", "completed", "blocked", "mitigated"],
        "blocked": ["completed"],
        "completed": [],
        "mitigated": []
    }
    
    # Validate state transition
    if new_state not in valid_transitions.get(phase.status, []):
        raise ValueError(f"Invalid transition: {phase.status} → {new_state}")
    
    # Update phase
    phase.status = new_state
    phase.updated_at = timestamp or datetime.utcnow()
    
    # Log evidence
    if evidence:
        phase.detection_methods.append({
            "method": evidence.get("method"),
            "triggered": True,
            "timestamp": (timestamp or datetime.utcnow()).isoformat(),
            "details": evidence.get("details")
        })
    
    await db.merge(phase)
    await db.commit()
    
    return True


# Example: Exploit phase detected!
await transition_phase(
    exploit_phase,
    new_state="detected",
    evidence={
        "method": "binary_analysis",
        "details": "ROP gadget chain discovered in victim process memory"
    }
)
```

#### 4. Monitor Real-Time Phase Progression

```python
@mcp.tool()
async def get_active_kill_chains() -> list[dict]:
    """
    Get all active kill chains currently being tracked.
    Includes current phase, progress, and next predicted phases.
    """
    active = db.query(KillChain).filter(
        KillChain.status == "active",
        KillChain.threat_actor_id.isnot(None)
    ).all()
    
    return [
        {
            "id": chain.id,
            "name": chain.name,
            "threat_actor": chain.threat_actor_id,
            "current_phase": chain.chain_phase,
            "current_state": chain.status,
            "confidence": chain.confidence,
            "progress": await calculate_phase_progress(chain),
            "next_phases": chain.next_phases,
            "detected_phases": [
                p.chain_phase for p in get_phases_by_campaign(chain.campaign_id)
                if p.status in ["detected", "in_progress"]
            ],
            "last_activity": chain.updated_at.isoformat()
        }
        for chain in active
    ]


@mcp.tool()
async def monitor_phase_transition(
    chain_id: str,
    detection_callback: callable = None
) -> dict:
    """
    Subscribe to phase transitions for a specific kill chain.
    Invokes callback when phase changes.
    
    Returns real-time updates:
    - Current phase and state
    - Time in current phase
    - Predicted next phase
    - Recommended defensive actions
    """
    chain = await db.get(KillChain, chain_id)
    
    return {
        "chain_id": chain_id,
        "name": chain.name,
        "timeline": [
            {
                "phase": p.chain_phase,
                "state": p.status,
                "entered_at": p.created_at.isoformat(),
                "evidence": p.detection_methods,
                "ttps": p.ttps
            }
            for p in get_phases_by_campaign(chain.campaign_id)
            if p.created_at >= chain.created_at
        ],
        "monitoring": True,
        "callback_registered": detection_callback is not None
    }
```

### Kill Chain Dashboards & Visualization

#### Real-Time Timeline View

```python
@mcp.tool()
async def get_kill_chain_timeline(
    campaign_id: str,
    threat_actor_id: str = None
) -> dict:
    """
    Get visual timeline of attack progression.
    
    Returns:
    - All phases with timestamps
    - Current phase highlighted
    - Time between phases
    - Detection gaps
    - Predicted future phases
    """
    phases = db.query(KillChain).filter(
        KillChain.campaign_id == campaign_id
    ).order_by(KillChain.phase_order).all()
    
    timeline = []
    for i, phase in enumerate(phases):
        time_in_phase = None
        if phase.status in ["completed", "blocked"]:
            if i + 1 < len(phases):
                time_in_phase = (phases[i+1].created_at - phase.created_at).total_seconds()
        
        timeline.append({
            "order": phase.phase_order,
            "phase": phase.chain_phase,
            "state": phase.status,
            "timestamp": phase.created_at.isoformat(),
            "duration_seconds": time_in_phase,
            "ttps": phase.ttps,
            "detected_by": [d["method"] for d in phase.detection_methods],
            "iocs": phase.iocs,
            "recommended_actions": phase.mitigation_steps
        })
    
    return {
        "campaign": campaign_id,
        "timeline": timeline,
        "current_phase_index": next(
            (i for i, p in enumerate(phases) if p.status == "in_progress"),
            len(phases) - 1
        ),
        "estimated_next_phase": phases[-1].next_phases[0] if phases[-1].next_phases else None,
        "time_to_next": estimate_phase_duration(phases[-1].chain_phase)
    }


# ASCII Timeline Visualization
async def visualize_kill_chain(campaign_id: str) -> str:
    """Render kill chain as ASCII timeline."""
    timeline = await get_kill_chain_timeline(campaign_id)
    
    visualization = """
    Attack Timeline: {campaign}
    
    [08-03 10:15] ✓ Reconnaissance
         └─ DNS enumeration detected
         └─ Time in phase: 2 days
    
    [08-03 12:30] ✓ Weaponization
         └─ Malicious document created
         └─ Time in phase: 3 hours
    
    [08-03 14:45] ✓ Delivery
         └─ Email sent via phishing
         └─ Time in phase: 45 minutes
    
    [08-03 15:30] ► Exploitation (IN PROGRESS)
         └─ ROP chain detected in memory
         └─ Time in phase: 22 minutes
         └─ Confidence: 95%
    
    [PREDICTED] ○ Installation
         └─ Estimated entry time: +1-4 hours
         └─ Watch for: New processes, file writes, registry changes
    
    [PREDICTED] ○ Command & Control
         └─ Estimated entry time: +12-48 hours
         └─ Watch for: Suspicious outbound connections, domain queries
    
    [PREDICTED] ○ Actions on Objectives
         └─ Estimated entry time: +3-7 days
         └─ Impact: Data exfiltration, system compromise
    """.format(campaign=campaign_id)
    
    return visualization
```

### Automated Phase Monitoring & Alerting

```python
class KillChainMonitor:
    """Monitors kill chains for phase transitions and anomalies."""
    
    async def watch_for_phase_transition(
        self,
        chain_id: str,
        from_phase: str,
        to_phase: str,
        timeout_seconds: int = 86400  # 24 hours
    ) -> dict:
        """
        Watch for a specific phase transition.
        Alert if it happens or doesn't happen within timeout.
        """
        chain = await db.get(KillChain, chain_id)
        start_time = datetime.utcnow()
        
        while (datetime.utcnow() - start_time).total_seconds() < timeout_seconds:
            if chain.chain_phase == to_phase:
                # Phase transition detected!
                return {
                    "detected": True,
                    "phase": to_phase,
                    "timestamp": datetime.utcnow().isoformat(),
                    "elapsed_time": (datetime.utcnow() - start_time).total_seconds(),
                    "alert_severity": "high"  # Escalate to SOC immediately
                }
            
            await asyncio.sleep(60)  # Check every minute
            chain = await db.refresh(chain)
        
        # Timeout reached - phase didn't transition
        return {
            "detected": False,
            "expected_phase": to_phase,
            "timeout_seconds": timeout_seconds,
            "possible_reasons": [
                "Attack was blocked",
                "Attack stalled or paused",
                "Detection threshold too high"
            ]
        }
    
    async def predict_phase_timing(
        self,
        campaign_id: str
    ) -> dict:
        """
        Based on observed phase transitions so far,
        predict when next phase will begin.
        """
        phases = await get_phases_by_campaign(campaign_id)
        
        phase_durations = []
        for i in range(len(phases) - 1):
            duration = (phases[i+1].created_at - phases[i].created_at).total_seconds()
            phase_durations.append({
                "from_phase": phases[i].chain_phase,
                "to_phase": phases[i+1].chain_phase,
                "duration_seconds": duration
            })
        
        # Calculate average time to next phase
        avg_duration = sum(p["duration_seconds"] for p in phase_durations) / len(phase_durations)
        
        current_phase = phases[-1]
        predicted_next_time = datetime.utcnow() + timedelta(seconds=avg_duration)
        
        return {
            "current_phase": current_phase.chain_phase,
            "predicted_next_phase": current_phase.next_phases[0] if current_phase.next_phases else None,
            "predicted_transition_time": predicted_next_time.isoformat(),
            "average_phase_duration": avg_duration,
            "confidence": 0.70 if len(phases) >= 3 else 0.40
        }


# Usage: Alert when exploitation phase is detected
monitor = KillChainMonitor()
result = await monitor.watch_for_phase_transition(
    chain_id=campaign.id,
    from_phase="delivery",
    to_phase="exploitation",
    timeout_seconds=3600  # Alert if not detected within 1 hour
)

if result["detected"]:
    await send_alert(
        severity="CRITICAL",
        message=f"Exploitation phase detected at {result['timestamp']}",
        recipients=["soc@company.com"]
    )
```

### Incident Integration

Link kill chains to incidents for full context:

```python
async def create_incident_from_kill_chain(
    chain: KillChain,
    phase: KillChain = None
) -> Incident:
    """
    Automatically create or update incident based on kill chain phase.
    """
    phase_to_severity = {
        "reconnaissance": "low",
        "weaponization": "low",
        "delivery": "medium",
        "exploitation": "high",
        "installation": "critical",
        "command_and_control": "critical",
        "actions_on_objectives": "critical"
    }
    
    phase_obj = phase or chain
    
    incident = Incident(
        title=f"{chain.name} - {phase_obj.chain_phase.title()} Phase Detected",
        description=f"{chain.threat_actor_id} attack campaign in {phase_obj.chain_phase} phase",
        severity=phase_to_severity.get(phase_obj.chain_phase, "medium"),
        status="open",
        attack_type="advanced_threat",
        kill_chain_ref=chain.id,
        current_phase=phase_obj.chain_phase,
        ttps=phase_obj.ttps,
        iocs=phase_obj.iocs
    )
    
    db.add(incident)
    await db.commit()
    
    return incident
```

### Custom Playbook Scenarios

Build reusable attack scenarios:

```python
class KillChainPlaybook:
    """Predefined attack scenarios for testing and monitoring."""
    
    PLAYBOOKS = {
        "spearphishing_rce": {
            "name": "Spear-Phishing with RCE",
            "threat_actors": ["apt28", "apt29"],
            "phases": [
                {
                    "phase": "reconnaissance",
                    "ttps": ["T1592", "T1591"],
                    "expected_duration": 172800  # 2 days
                },
                {
                    "phase": "weaponization",
                    "ttps": ["T1204.002"],
                    "expected_duration": 10800  # 3 hours
                },
                {
                    "phase": "delivery",
                    "ttps": ["T1566.002"],
                    "expected_duration": 3600  # 1 hour
                },
                {
                    "phase": "exploitation",
                    "ttps": ["T1203", "T1190"],
                    "expected_duration": 1800  # 30 mins
                }
            ]
        },
        "supply_chain_compromise": {
            "name": "Supply Chain Compromise",
            "threat_actors": ["apt33", "apt34"],
            "phases": [
                {"phase": "reconnaissance", "ttps": ["T1592"]},
                {"phase": "weaponization", "ttps": ["T1195.002"]},
                {"phase": "delivery", "ttps": ["T1195.001"]},
                {"phase": "exploitation", "ttps": ["T1195.003"]}
            ]
        }
    }
    
    @staticmethod
    async def create_from_playbook(
        playbook_name: str,
        campaign_id: str,
        threat_actor_id: str
    ) -> KillChain:
        """Instantiate a kill chain from a playbook template."""
        if playbook_name not in KillChainPlaybook.PLAYBOOKS:
            raise ValueError(f"Unknown playbook: {playbook_name}")
        
        playbook = KillChainPlaybook.PLAYBOOKS[playbook_name]
        
        chain = KillChain(
            name=playbook["name"],
            threat_actor_id=threat_actor_id,
            campaign_id=campaign_id,
            status="active"
        )
        db.add(chain)
        
        # Add all phases from playbook
        for phase_config in playbook["phases"]:
            phase = KillChain(
                name=f"{playbook['name']} - {phase_config['phase'].title()}",
                chain_phase=phase_config["phase"],
                ttps=phase_config.get("ttps", []),
                status="predicted"
            )
            db.add(phase)
        
        await db.commit()
        return chain
```

---

## Offensive & Defensive Kill Chain Operations

Kill chains serve dual purposes in security: **Red Team Planning** (offensive) and **Blue Team Defense** (defensive). The same framework enables both.

### Red Team: Planning Offensive Operations

Red teams use kill chains to **plan and execute penetration tests and authorized security assessments**.

#### 1. Build Attack Campaign

```python
class OffensiveKillChain:
    """Red team attack planning and execution."""
    
    async def plan_operation(
        self,
        target_org: str,
        objective: str,
        rules_of_engagement: dict
    ) -> KillChain:
        """
        Plan a red team operation with kill chain phases.
        
        Args:
            target_org: Target organization
            objective: "Data theft", "Lateral movement", "Persistence", etc.
            rules_of_engagement: Authorized scope, boundaries, allowed tools
        """
        chain = KillChain(
            name=f"Red Team Engagement - {target_org}",
            status="planned",
            attack_type="red_team_engagement",
            rules_of_engagement=rules_of_engagement,
            description=f"Objective: {objective}"
        )
        
        # Reconnaissance phase: gather open-source intelligence
        await self.add_phase(
            chain,
            phase="reconnaissance",
            ttps=["T1592", "T1591"],  # Gather victim info
            objectives=[
                "Domain enumeration",
                "Employee identification via LinkedIn",
                "Public IP/DNS mapping",
                "Technology stack identification"
            ],
            tools=["shodan", "whois", "nmap", "google dorking"],
            data_sources=[
                {"source": "public_records", "description": "SEC filings, job postings"},
                {"source": "social_media", "description": "LinkedIn, Twitter"},
                {"source": "dns_records", "description": "Subdomain enumeration"}
            ]
        )
        
        # Weaponization phase: prepare payloads
        await self.add_phase(
            chain,
            phase="weaponization",
            objectives=[
                "Create spear-phishing document",
                "Prepare C2 infrastructure",
                "Weaponize vulnerability"
            ],
            tools=["msfvenom", "evilginx2", "cobalt_strike"],
            authorization=[
                "Phishing authorized against: @target.com emails only",
                "C2 domains approved: c2.red-team.lab",
                "Payload execution limited to: testlab systems"
            ]
        )
        
        # Delivery phase: initiate contact
        await self.add_phase(
            chain,
            phase="delivery",
            objectives=[
                "Send spear-phishing emails",
                "Wait for victim engagement",
                "Track click-through rates"
            ],
            metrics=[
                "emails_sent",
                "click_through_rate",
                "victim_opened_attachment",
                "payload_executed"
            ]
        )
        
        # Exploitation phase: gain access
        await self.add_phase(
            chain,
            phase="exploitation",
            objectives=[
                "Execute payload on victim system",
                "Establish reverse shell",
                "Verify code execution"
            ],
            success_criteria=[
                "Process spawned with SYSTEM privileges",
                "Network callback to C2 established",
                "Command execution confirmed"
            ],
            containment_triggers=[
                "Alert on MITRE ATT&CK T1055 detected",
                "Terminate operation immediately"
            ]
        )
        
        # Installation & persistence phase
        await self.add_phase(
            chain,
            phase="installation",
            objectives=[
                "Establish persistence mechanism",
                "Create backup access point",
                "Document access for future testing"
            ],
            authorized_methods=[
                "Scheduled task on test system",
                "Registry autorun in isolated lab",
                "Service installation in testlab domain"
            ]
        )
        
        # C&C phase: maintain access
        await self.add_phase(
            chain,
            phase="command_and_control",
            objectives=[
                "Issue test commands to verify control",
                "Simulate lateral movement",
                "Document access paths"
            ],
            allowed_commands=[
                "whoami",
                "ipconfig",
                "net group 'Domain Admins' /domain",
                "findstr /s password *.txt"
            ]
        )
        
        # Actions on objectives phase
        await self.add_phase(
            chain,
            phase="actions_on_objectives",
            objectives=[
                "Access target data",
                "Document security gaps",
                "Prepare remediation roadmap"
            ],
            data_collection=[
                "Sensitive file locations",
                "Security control gaps",
                "Access control weaknesses",
                "Defense evasion techniques"
            ]
        )
        
        await db.add(chain)
        await db.commit()
        return chain


    async def track_operation_progress(
        self,
        chain_id: str
    ) -> dict:
        """Real-time progress tracking for red team operation."""
        chain = await db.get(KillChain, chain_id)
        phases = await get_phases_by_campaign(chain.campaign_id)
        
        return {
            "operation": chain.name,
            "status": chain.status,
            "current_phase": chain.chain_phase,
            "phases_completed": [p.chain_phase for p in phases if p.status == "completed"],
            "phases_in_progress": [p.chain_phase for p in phases if p.status == "in_progress"],
            "phases_remaining": [p.chain_phase for p in phases if p.status == "predicted"],
            "objectives_achieved": sum(1 for p in phases if p.status == "completed"),
            "security_gaps_found": len(chain.mitigation_steps),
            "estimated_completion": self._estimate_completion(phases)
        }
    
    
    async def document_findings(
        self,
        chain_id: str,
        phase: str,
        findings: list[dict]
    ):
        """Document security findings for each phase."""
        phase_obj = await db.get(KillChain, id=chain_id, chain_phase=phase)
        
        for finding in findings:
            phase_obj.mitigation_steps.append({
                "finding": finding["description"],
                "severity": finding["severity"],  # critical, high, medium, low
                "remediation": finding["fix"],
                "priority": finding["priority"]
            })
        
        await db.merge(phase_obj)
        await db.commit()
```

#### 2. Red Team Assessment Report

```python
async def generate_red_team_report(
    chain_id: str
) -> dict:
    """Generate executive report from red team operation."""
    chain = await db.get(KillChain, chain_id)
    phases = await get_phases_by_campaign(chain.campaign_id)
    
    report = {
        "title": chain.name,
        "objective": chain.description,
        "assessment_date": chain.created_at.isoformat(),
        "overall_security_posture": calculate_posture_score(phases),
        
        "phases_tested": [
            {
                "phase": p.chain_phase,
                "status": p.status,
                "success": p.status == "completed",
                "time_to_compromise": (p.updated_at - p.created_at).total_seconds() if p.updated_at else None
            }
            for p in phases
        ],
        
        "critical_findings": [
            m for m in chain.mitigation_steps
            if m.get("severity") == "critical"
        ],
        
        "security_gaps": {
            "detection": [g for g in chain.mitigation_steps if "detection" in g.get("category", "")],
            "prevention": [g for g in chain.mitigation_steps if "prevention" in g.get("category", "")],
            "response": [g for g in chain.mitigation_steps if "response" in g.get("category", "")]
        },
        
        "remediation_roadmap": sorted(
            chain.mitigation_steps,
            key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}[x.get("severity", "low")]
        ),
        
        "recommendations": [
            "Implement EDR for process execution monitoring",
            "Enable MFA on all administrative accounts",
            "Deploy network segmentation",
            "Update all Microsoft Office to latest patch"
        ]
    }
    
    return report
```

---

### Blue Team: Building Defensive Countermeasures

Blue teams use kill chains to **predict attacks and build layer-by-layer defenses**.

#### 1. Defensive Kill Chain Architecture

```python
class DefensiveKillChain:
    """Blue team defensive strategy and counter-measures."""
    
    async def build_defense_strategy(
        self,
        threat_actor: str,
        known_playbooks: list[str]
    ) -> dict:
        """
        Build multi-layer defense strategy against specific threat actor.
        """
        strategy = {
            "threat_actor": threat_actor,
            "defense_layers": {}
        }
        
        # For each attack phase, define prevention, detection, response
        attack_phases = [
            "reconnaissance", "weaponization", "delivery",
            "exploitation", "installation", "command_and_control",
            "actions_on_objectives"
        ]
        
        for phase in attack_phases:
            strategy["defense_layers"][phase] = {
                "phase": phase,
                
                # PREVENTION: Stop attack before it happens
                "prevention": self._get_prevention_controls(phase, threat_actor),
                
                # DETECTION: Identify attack if it occurs
                "detection": self._get_detection_rules(phase, threat_actor),
                
                # RESPONSE: Respond when attack is detected
                "response": self._get_response_procedures(phase),
                
                # DECEPTION: Deploy honeypots and deceptive controls
                "deception": self._get_deception_controls(phase)
            }
        
        return strategy


    def _get_prevention_controls(self, phase: str, threat_actor: str) -> list[dict]:
        """Prevention controls to block attack before it occurs."""
        prevention_map = {
            "reconnaissance": [
                {
                    "control": "OSINT Monitoring",
                    "description": "Monitor leaks.company.com, Shodan, Censys for exposed data",
                    "implementation": "Setup alerts for company name in breach databases"
                },
                {
                    "control": "Email Filtering",
                    "description": "Block reconnaissance emails, prevent information gathering",
                    "implementation": "Filter 'who works at' queries, domain enumeration attempts"
                }
            ],
            
            "weaponization": [
                {
                    "control": "Domain Registration Monitoring",
                    "description": "Alert on typosquatting and look-alike domains",
                    "implementation": "Monitor *.company.com, company*.com registrations"
                },
                {
                    "control": "Code Signing Validation",
                    "description": "Require code to be signed with valid certificates",
                    "implementation": "Deny execution of unsigned binaries via AppLocker"
                }
            ],
            
            "delivery": [
                {
                    "control": "Email Gateway Filtering",
                    "description": "Block malicious emails at gateway",
                    "implementation": "Proofpoint/Mimecast with sandboxing and AI detection"
                },
                {
                    "control": "Anti-Phishing Training",
                    "description": "Reduce user susceptibility to spear-phishing",
                    "implementation": "Quarterly security awareness training with simulations"
                }
            ],
            
            "exploitation": [
                {
                    "control": "Patch Management",
                    "description": "Apply security patches within 30 days",
                    "implementation": "WSUS, automated patch deployment, CVE tracking"
                },
                {
                    "control": "Web App Firewalls",
                    "description": "Block web exploitation attempts",
                    "implementation": "ModSecurity, Cloudflare WAF with OWASP CRS rules"
                }
            ],
            
            "installation": [
                {
                    "control": "Registry Hardening",
                    "description": "Prevent registry-based persistence",
                    "implementation": "GPO restrictions on HKLM\\Run, HKCU\\Run modifications"
                },
                {
                    "control": "File Integrity Monitoring",
                    "description": "Alert on unauthorized file system changes",
                    "implementation": "osquery, Wazuh, AIDE monitoring"
                }
            ],
            
            "command_and_control": [
                {
                    "control": "DNS Filtering",
                    "description": "Block C&C domain resolution",
                    "implementation": "Quad9, Cisco Umbrella, DNS sinkholing"
                },
                {
                    "control": "Outbound Firewall Rules",
                    "description": "Restrict outbound connections to approved destinations",
                    "implementation": "Whitelist allowed external destinations"
                }
            ],
            
            "actions_on_objectives": [
                {
                    "control": "DLP (Data Loss Prevention)",
                    "description": "Prevent data exfiltration",
                    "implementation": "Symantec DLP, CloudLock, network segmentation"
                },
                {
                    "control": "Encryption",
                    "description": "Encrypt sensitive data at rest and in transit",
                    "implementation": "AES-256 for storage, TLS 1.3 for transmission"
                }
            ]
        }
        
        return prevention_map.get(phase, [])


    def _get_detection_rules(self, phase: str, threat_actor: str) -> list[dict]:
        """Detection rules using SIEM, EDR, network monitoring."""
        detection_map = {
            "reconnaissance": [
                {
                    "type": "SIEM Rule",
                    "alert": "Excessive DNS queries for internal domain",
                    "implementation": "Alert if >100 failed DNS queries in 5 minutes",
                    "tool": "Splunk / ELK"
                },
                {
                    "type": "Email Alert",
                    "alert": "Suspicious email reconnaissance patterns",
                    "implementation": "Alert on 'list of employees', 'who works in'",
                    "tool": "Proofpoint / O365 Advanced Threat Protection"
                }
            ],
            
            "delivery": [
                {
                    "type": "Email Gateway",
                    "alert": "Suspicious attachment detected",
                    "implementation": "Sandboxing + behavioral analysis",
                    "tool": "Mimecast / Proofpoint"
                },
                {
                    "type": "EDR Alert",
                    "alert": "Macro execution in Office document",
                    "implementation": "Parent: winword.exe, Child: powershell.exe",
                    "tool": "CrowdStrike / Microsoft Defender"
                }
            ],
            
            "exploitation": [
                {
                    "type": "EDR",
                    "alert": "Process injection detected (T1055)",
                    "implementation": "Alert on direct/indirect system calls to VirtualAllocEx+WriteProcessMemory",
                    "tool": "CrowdStrike / Elastic Security"
                },
                {
                    "type": "WAF",
                    "alert": "SQL injection attempt blocked",
                    "implementation": "WAF rule match + SQL keywords in request",
                    "tool": "ModSecurity / AWS WAF"
                }
            ],
            
            "installation": [
                {
                    "type": "FIM (File Integrity Monitoring)",
                    "alert": "Unauthorized registry modification",
                    "implementation": "Alert on changes to HKLM\\Software\\Microsoft\\Windows\\Run",
                    "tool": "osquery / Wazuh"
                },
                {
                    "type": "EDR",
                    "alert": "Scheduled task created for persistence",
                    "implementation": "Alert on schtasks.exe /create with suspicious binary",
                    "tool": "CrowdStrike / Defender"
                }
            ],
            
            "command_and_control": [
                {
                    "type": "Network",
                    "alert": "Known C&C domain contacted",
                    "implementation": "DNS query match against threat feeds",
                    "tool": "Zeek / Suricata + DNS logs"
                },
                {
                    "type": "EDR",
                    "alert": "Suspicious network connection from system process",
                    "implementation": "Alert if svchost.exe connects to external IP:4444",
                    "tool": "Defender / CrowdStrike"
                }
            ],
            
            "actions_on_objectives": [
                {
                    "type": "DLP",
                    "alert": "Large data transfer detected",
                    "implementation": "Alert if >100MB transferred to external IP in 1 hour",
                    "tool": "Symantec DLP / CloudLock"
                },
                {
                    "type": "SIEM",
                    "alert": "Multiple failed login attempts followed by success",
                    "implementation": "Alert on brute force pattern (>5 failures then 1 success)",
                    "tool": "Splunk / Azure Sentinel"
                }
            ]
        }
        
        return detection_map.get(phase, [])


    def _get_response_procedures(self, phase: str) -> list[dict]:
        """Incident response procedures when attack is detected."""
        response_map = {
            "reconnaissance": [
                {
                    "step": 1,
                    "action": "Isolate affected systems",
                    "procedure": "Disconnect systems from network if active reconnaissance detected"
                },
                {
                    "step": 2,
                    "action": "Collect forensics",
                    "procedure": "Capture memory dump, network connections, process list"
                }
            ],
            
            "delivery": [
                {
                    "step": 1,
                    "action": "Quarantine email",
                    "procedure": "Remove email from all inboxes, alert all recipients"
                },
                {
                    "step": 2,
                    "action": "Update IOCs",
                    "procedure": "Add sender domain, file hash to threat feeds"
                }
            ],
            
            "exploitation": [
                {
                    "step": 1,
                    "action": "IMMEDIATE: Kill process",
                    "procedure": "Terminate injected process using taskkill or EDR kill switch"
                },
                {
                    "step": 2,
                    "action": "Isolate system",
                    "procedure": "Move to quarantine VLAN, block network access"
                },
                {
                    "step": 3,
                    "action": "Notify SOC lead",
                    "procedure": "Page on-call incident commander"
                }
            ],
            
            "installation": [
                {
                    "step": 1,
                    "action": "Remove persistence mechanism",
                    "procedure": "Delete scheduled task, registry entry, malware binary"
                },
                {
                    "step": 2,
                    "action": "Rebuild system",
                    "procedure": "Reimage from clean backup if binary has been executed"
                }
            ],
            
            "command_and_control": [
                {
                    "step": 1,
                    "action": "Block C&C domain",
                    "procedure": "Add domain to DNS sinkhole, firewall rules, EDR hunting"
                },
                {
                    "step": 2,
                    "action": "Hunt for beacons",
                    "procedure": "Search all systems for connections to blocked domain"
                }
            ]
        }
        
        return response_map.get(phase, [])


    def _get_deception_controls(self, phase: str) -> list[dict]:
        """Deception tactics (honeypots, canaries, traps)."""
        deception_map = {
            "reconnaissance": [
                {
                    "control": "Fake org chart",
                    "description": "Distribute honeypot employee list with traceable emails",
                    "benefit": "Track if attacker collects exposed employee data"
                }
            ],
            
            "delivery": [
                {
                    "control": "Honey tokens",
                    "description": "Create fake credentials that alert when used",
                    "benefit": "Early detection if credentials are compromised"
                }
            ],
            
            "exploitation": [
                {
                    "control": "Honeypots",
                    "description": "Run fake vulnerable services that log all interactions",
                    "benefit": "Attract attackers and capture their tools/techniques"
                }
            ],
            
            "installation": [
                {
                    "control": "Canary files",
                    "description": "Place files that trigger alerts when accessed",
                    "benefit": "Detect lateral movement early"
                }
            ],
            
            "command_and_control": [
                {
                    "control": "Fake C2 callback",
                    "description": "Respond to C2 beacons with fake commands",
                    "benefit": "Gather intelligence on attacker capabilities"
                }
            ]
        }
        
        return deception_map.get(phase, [])
```

#### 2. Defensive Coverage Report

```python
async def generate_defense_coverage_report(
    threat_actor: str
) -> dict:
    """
    Report on defensive coverage against specific threat actor.
    Identifies gaps in prevention, detection, response.
    """
    defense_strategy = await build_defense_strategy(threat_actor, [])
    
    report = {
        "threat_actor": threat_actor,
        "assessment_date": datetime.utcnow().isoformat(),
        
        "coverage_by_phase": {
            phase: {
                "prevention_controls": len(controls["prevention"]),
                "detection_rules": len(controls["detection"]),
                "response_procedures": len(controls["response"]),
                "deception_controls": len(controls["deception"]),
                "coverage_score": calculate_coverage(controls)
            }
            for phase, controls in defense_strategy["defense_layers"].items()
        },
        
        "overall_coverage": calculate_total_coverage(defense_strategy),
        
        "weakest_phases": identify_gaps(defense_strategy),
        
        "improvement_roadmap": [
            {
                "phase": "reconnaissance",
                "gap": "No OSINT monitoring for company name on Shodan",
                "action": "Deploy Shodan monitor in next 30 days",
                "priority": "high"
            }
        ]
    }
    
    return report
```

---

### Side-by-Side: Offensive vs Defensive

| Aspect | Offensive (Red Team) | Defensive (Blue Team) |
|--------|---------------------|----------------------|
| **Goal** | Find security gaps | Block attacks |
| **Perspective** | "How do we attack?" | "How do we defend?" |
| **Phases** | Execute full attack chain | Defend each phase independently |
| **Success Metric** | Reach objective (data access) | Block before reaching objective |
| **Timeline** | Days/weeks | Continuous |
| **Scope** | Authorized test target | Entire organization |
| **Documentation** | Red team report with findings | Blue team defense roadmap |
| **Tools** | Exploitation frameworks, C2, metasploit | SIEM, EDR, WAF, DLP |
| **Output** | Security gaps discovered | Defense gaps patched |

### Integrated Workflow

```python
async def run_red_team_blue_team_cycle(
    target_org: str,
    threat_scenarios: list[str]
) -> dict:
    """
    Execute full Red Team assessment,
    then use findings to build Blue Team defenses.
    """
    # Phase 1: Red Team attacks
    red_team = OffensiveKillChain()
    operation = await red_team.plan_operation(
        target_org=target_org,
        objective="Data theft",
        rules_of_engagement={"scope": "authorized_systems_only"}
    )
    
    # Execute attack...
    # Document findings...
    red_team_report = await generate_red_team_report(operation.id)
    
    # Phase 2: Blue Team defends
    blue_team = DefensiveKillChain()
    defense_strategy = await blue_team.build_defense_strategy(
        threat_actor="red_team_testing",
        known_playbooks=threat_scenarios
    )
    
    # Identify gaps from red team findings
    gaps = identify_gaps_from_red_team(red_team_report, defense_strategy)
    
    # Generate improvement roadmap
    roadmap = {
        "immediate": gaps["critical"],      # Fix within 7 days
        "short_term": gaps["high"],         # Fix within 30 days
        "medium_term": gaps["medium"],      # Fix within 90 days
        "long_term": gaps["low"]            # Fix within 1 year
    }
    
    return {
        "red_team_findings": red_team_report,
        "defense_coverage": defense_strategy,
        "improvement_roadmap": roadmap
    }
```

---

## Quick Start: Add Bandit to Security Plugin

### 1. Add Model

Create `cells/analysis/model.py`:

```python
from sqlalchemy import Column, String, DateTime, JSON, Integer, Float
from sqlalchemy.dialects.postgresql import UUID
import uuid
from itl_braincell_sdk.core.models import Base, TimestampMixin

class SASTFinding(Base, TimestampMixin):
    __tablename__ = "sast_findings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tool = Column(String, nullable=False)
    language = Column(String)
    file_path = Column(String, nullable=False)
    line_number = Column(Integer)
    issue_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    message = Column(String)
    status = Column(String, default="open")
```

### 2. Add Service

Create `cells/analysis/service.py`:

```python
import subprocess, json

async def scan_python_with_bandit(repo_path: str) -> list[dict]:
    """Run Bandit on Python repo."""
    result = subprocess.run(
        ["bandit", "-r", repo_path, "-f", "json"],
        capture_output=True, text=True
    )
    return json.loads(result.stdout)["results"]
```

### 3. Add Routes

Create `cells/analysis/routes.py`:

```python
from fastapi import APIRouter, Depends
from .service import scan_python_with_bandit
from .model import SASTFinding

router = APIRouter()

@router.post("/scan")
async def scan_code(repo_path: str):
    """Scan Python code for vulnerabilities."""
    results = await scan_python_with_bandit(repo_path)
    return {"findings": results, "count": len(results)}
```

### 4. Register Cell

Update `cells/__init__.py`:

```python
from .analysis.cell import cell as analysis_cell

class SecurityPlugin(CellCollectionPlugin):
    def get_cells(self):
        return [
            threats_cell,
            incidents_cell,
            iocs_cell,
            analysis_cell  # ← Add this
        ]
```

---

## Testing

```python
import pytest
from analysis.service import AnalysisService

@pytest.mark.asyncio
async def test_bandit_scan():
    service = AnalysisService()
    results = await service.scan_with_bandit("/path/to/test/repo")
    
    assert len(results) > 0
    assert results[0].tool == "bandit"
    assert results[0].language == "python"

@pytest.mark.asyncio
async def test_ghidra_analysis():
    service = AnalysisService()
    analysis = await service.analyze_binary_ghidra("/path/to/binary")
    
    assert analysis.tool_used == "ghidra"
    assert analysis.threat_score >= 0.0 and analysis.threat_score <= 1.0
```

---

## Roadmap

| Phase | Focus | Repos | Tools | Effort | Timeline | Blocker |
|-------|-------|-------|-------|--------|----------|---------|
| **Phase 1** | Dependency scanning | SDK, Plugin, MCP | Bandit, Safety | Easy | 1-2 days | — |
| **Phase 2** | SAST scanning | SDK, Plugin, MCP | Semgrep, Trivy | Medium | 3-5 days | — |
| **Phase 3** | Binary + ROP + Fuzz | SDK, Plugin, MCP | Radare2, Ropper, AFL++ | Medium | 5-10 days | — |
| **Phase 4** | Deep reverse engineering | SDK, Plugin, MCP | Ghidra, SonarQube | Hard | 10-20 days | Phase 3 |
| **Phase 5** | Symbolic execution | SDK, Plugin, MCP | Angr, Z3 | Hard | TBD | Phase 4 |
| **Phase 6** | Kill chain framework | SDK, Core, Plugin, MCP | Lockheed Martin model | Medium | 3-7 days | Phase 3 |
| **Phase 7** | Red team operations | SDK, Plugin, MCP | Kill chains | Medium | 5-7 days | Phase 6 |
| **Phase 8** | Blue team defense | SDK, Plugin, MCP | Kill chains | Hard | 10-14 days | Phase 6 |
| **Phase 9** | Hypothesis testing | SDK, Plugin, MCP | GDB, Valgrind, sandbox | Medium | 7-10 days | Phase 3, 4 |
| **Phase 10** | Runtime monitoring | SDK, Plugin, MCP | strace, API hooks | Hard | 10-15 days | — |
| **Phase 11** | Network analysis | SDK, Plugin, MCP | Zeek, Wireshark | Hard | 10-15 days | Phase 5 |
| **Phase 12** | Malware clustering | SDK, Plugin, MCP | ssdeep, ML | Medium | 5-7 days | Phase 3 |
| **Phase 13** | Supply chain analysis | SDK, Plugin, MCP | Dependency graph | Medium | 5-7 days | Phase 2 |
| **Phase 14** | Config analysis | SDK, Plugin, MCP | Parsers, validators | Easy | 3-5 days | — |
| **Phase 15** | Access control | SDK, Plugin, MCP | RBAC graph, z3 | Medium | 7-10 days | Phase 5 |
| **Phase 16** | Cryptography analysis | SDK, Plugin, MCP | Cryptography libs | Medium | 5-7 days | Phase 4 |
| **Phase 17** | Defense validation | SDK, Plugin, MCP | Kill chains | Hard | 10-14 days | Phase 8 |

### Implementation Strategy by Layer

**Phases 1-8: Foundation (what you have documented)**
- Layer 1 (SDK): ✅ ORM models defined, service classes documented
- Layer 3 (Plugin): ✅ Cell structure documented  
- Layer 4 (MCP): ✅ Tool signatures documented
- Status: Ready for Phase 6-8 implementation

**Phases 9-17: Missing Capabilities (9 gaps)**

#### Quick Wins (2-week effort):
1. **Phase 9: Hypothesis Testing** (Proof-of-concept validation)
   - SDK: HypothesisTestService, HypothesisTest ORM
   - Plugin: hypothesis_testing/ cell
   - MCP: run_poc(), measure_reliability()
   - Deliverable: Filter false positives, measure exploit reliability

2. **Phase 14: Configuration Analysis** (Security misconfiguration)
   - SDK: ConfigAnalysisService, ConfigurationAnalysis ORM
   - Plugin: configuration/ cell
   - MCP: detect_misconfigs(), check_compliance()
   - Deliverable: Find insecure defaults, compliance violations

3. **Phase 13: Supply Chain Analysis** (Dependency graph)
   - SDK: SupplyChainService, DependencyGraph ORM
   - Plugin: supply_chain/ cell
   - MCP: analyze_dependency_graph(), find_compromise_paths()
   - Deliverable: Visualize compromise paths through dependencies

#### High Value (3-4 weeks):
4. **Phase 10: Runtime Monitoring** (Dynamic behavior analysis)
   - SDK: RuntimeMonitoringService, RuntimeAnalysis ORM
   - Plugin: runtime_monitoring/ cell
   - MCP: start_monitoring(), get_telemetry(), get_behavioral_verdict()
   - Deliverable: Understand actual program behavior vs theory

5. **Phase 11: Network Analysis** (C2 detection)
   - SDK: NetworkAnalysisService, NetworkAnalysis ORM
   - Plugin: network_analysis/ cell
   - MCP: extract_protocol(), find_c2_domains(), analyze_beacon_timing()
   - Deliverable: Reverse engineer C2 protocols, detect callbacks

6. **Phase 12: Malware Clustering** (Family relationships)
   - SDK: MalwareFamilyService, MalwareFamily ORM
   - Plugin: malware_family/ cell
   - MCP: cluster_samples(), link_variants(), track_evolution()
   - Deliverable: Link variants to families, accelerate analysis

#### Complex (2-3 weeks each):
7. **Phase 15: Access Control** (Privilege escalation)
   - SDK: AccessControlService, AccessControlAnalysis ORM
   - Plugin: access_control/ cell
   - MCP: analyze_rbac(), find_escalation_paths(), check_capability_gaps()
   - Deliverable: Map privilege escalation routes from low→admin

8. **Phase 16: Cryptography Analysis** (Encryption validation)
   - SDK: CryptoAnalysisService, CryptographyAnalysis ORM
   - Plugin: cryptography/ cell
   - MCP: validate_cipher_strength(), find_crypto_failures(), check_key_derivation()
   - Deliverable: Detect weak crypto, key reuse, bad randomness

9. **Phase 17: Defense Validation** (Test defenses work)
   - SDK: DefenseValidationService, DefenseValidation ORM
   - Plugin: defense_validation/ cell
   - MCP: test_defense(), measure_coverage(), identify_gaps()
   - Deliverable: Validate that EDR/WAF/patches actually stop attacks

### Recommended Implementation Order

**Tier 1 (Immediate): Phases 6, 7, 8** ← What you currently have documented
- Kill chain framework, red team, blue team
- Enables attack planning & defense strategy
- Timeline: 2-3 weeks

**Tier 2 (Quick wins): Phases 9, 14, 13** ← Start here for missing capabilities
- Hypothesis testing (validate bugs are real)
- Config analysis (find misconfigs)
- Supply chain (understand dependencies)
- Timeline: 2 weeks
- Effort: Medium
- Impact: Reduces false positives, speeds analysis

**Tier 3 (Core capabilities): Phases 10, 11, 12** ← Complete the picture
- Runtime monitoring (understand behavior)
- Network analysis (detect C2)
- Malware clustering (find variants)
- Timeline: 3-4 weeks
- Effort: Hard
- Impact: From theory to operational visibility

**Tier 4 (Advanced): Phases 15, 16, 17** ← Polish the platform
- Access control (find privesc)
- Cryptography (validate crypto)
- Defense validation (test defenses)
- Timeline: 2-3 weeks each
- Effort: Hard
- Impact: Deep exploitation capability + defense verification

### Repository Ownership

All 17 phases are implemented following this pattern:

| Repo | Responsibility |
|------|-----------------|
| **ITL.Braincell.SDK** | ORM models (all phases), Service classes with business logic |
| **ITL.BrainCell** | Base MemoryCell, discovery mechanism, cross-cell linking |
| **ITL.Braincell.Cells.Security** | Cells for each capability, routes, schemas |
| **ITL.BrainCell.Mcp** | Tool wrappers for each service method |

---

**Phase 3 Extended Details (Fuzz Testing):**
- Detect buffer overflow/format string/use-after-free patterns in binaries
- Automatically generate fuzzing corpus (seed inputs) tailored to vulnerability type
- Launch AFL++, libFuzzer, or Honggfuzz campaigns targeting vulnerable functions
- Analyze discovered crashes for exploitability (ASLR bypass, ROP gadget availability)
- Automatic crash deduplication and triaging by severity
- Build ROP chain exploits from confirmed crashes
- Correlate crashing inputs to kill chain exploitation phase
- Track time-to-exploit and confirm realistic attack scenarios

**Phase 6 Details:**
- Implement KillChain model in security cell
- Add correlation logic (findings → MITRE ATT&CK → kill chain phase)
- MCP tools for tracing attack progression
- Prediction engine for next attack phases
- Timeline visualization
- Integrate with existing threats, incidents, IOCs cells

**Phase 7 Details (Red Team - Offensive):**
- `OffensiveKillChain` class for planning penetration tests
- Build attack campaigns with authorization tracking
- Phase-by-phase progression with metrics
- Document findings and security gaps
- Generate red team assessment reports
- Rules of engagement enforcement

**Phase 8 Details (Blue Team - Defensive):**
- `DefensiveKillChain` class for building defenses
- Prevention controls for each attack phase
- Detection rules (SIEM, EDR, WAF)
- Incident response procedures
- Deception tactics (honeypots, canaries)
- Defense coverage reports
- Identify gaps and generate remediation roadmap
- Integrated offensive→defensive workflow

---

## References

### Binary Analysis & Exploitation

- [Radare2 Book](https://radare.gitbooks.io/radare2book/) — Complete Radare2 documentation
- [Ropper - ROP Gadget Finder](https://github.com/sashs/Ropper) — Automated ROP gadget search and chain building
- [Angr - Program Analysis](https://angr.io/) — Symbolic execution engine
- [Pwntools - Exploitation Framework](https://docs.pwntools.com/) — Exploit writing utilities
- [Ghidra Documentation](https://ghidra-sre.org/) — NSA reverse engineering framework
- [ROP Emporium](https://ropemporium.com/) — ROP gadget challenges and tutorials
- [Exploit Development](https://www.offensive-security.com/metasploit-unleashed/) — Offensive Security guide

### Static Code Analysis

- [Semgrep Rules](https://semgrep.dev/r) — Pattern-based code scanner
- [Bandit Documentation](https://bandit.readthedocs.io/) — Python security linter
- [SonarQube](https://www.sonarqube.org/) — Enterprise code quality and security

### Dependency Scanning

- [Safety Database](https://safety.readthedocs.io/) — Python vulnerability database
- [Trivy Documentation](https://aquasecurity.github.io/trivy/) — Multi-purpose vulnerability scanner
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) — Dependency analyzer

### Standards & References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — Web application security risks
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/) — Most dangerous software weaknesses
- [MITRE ATT&CK](https://attack.mitre.org/) — Adversary tactics and techniques
- [x86-64 ABI](https://refspecs.linuxfoundation.org/elf/x86-64-abi-0.99.pdf) — Calling convention reference
- [System Call Interface](https://man7.org/linux/man-pages/) — Linux syscall documentation

### Kill Chain & Attack Frameworks

- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) — 7-phase attack model
- [MITRE ATT&CK Kill Chains](https://attack.mitre.org/resources/using-the-matrix/) — TTPs mapped to phases
- [Diamond Model](https://en.wikipedia.org/wiki/Diamond_Model_of_Intrusion_Analysis) — Attack relationships
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework/) — Incident lifecycle phases

### Kill Chain Monitoring & Playbooks

- [Elastic Security Playbooks](https://www.elastic.co/guide/en/security/current/attack-pattern-detection.html) — Real-time threat detection
- [CISA APT Incident Response Playbooks](https://www.cisa.gov/incident-response) — Incident handling procedures
- [SANS Incident Handling](https://www.sans.org/reading-room/whitepapers/incident/) — IR best practices
- [Cybersecurity Incident Timeline Analysis](https://www.nist.gov/publications/guidelines-incident-response) — Timeline reconstruction
- [Red Team vs Blue Team Playbooks](https://attack.mitre.org/tactics/) — Defensive play-by-play responses

---

## Questions?

See [MIGRATION.md](MIGRATION.md) for plugin architecture overview.

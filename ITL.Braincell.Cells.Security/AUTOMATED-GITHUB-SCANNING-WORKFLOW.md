# Automated GitHub Repository Vulnerability Scanning Workflow

**Objective**: Deploy an AI agent that autonomously scans the top 100 most-used GitHub repositories to discover, analyze, and report security vulnerabilities.

**Timeline**: Implement in 2-3 weeks using Phases 1-3 of the security analysis roadmap
**Output**: Daily vulnerability reports with exploitability assessment, impact analysis, and remediation recommendations

---

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│ AGENT ORCHESTRATOR (LLM-Based Autonomous Agent)                      │
├──────────────────────────────────────────────────────────────────────┤
│ Responsibilities:                                                     │
│ • Determine which repos to scan (top 100 by stars/forks)            │
│ • Schedule daily/weekly scans                                       │
│ • Call SDK service methods via MCP tools                            │
│ • Coordinate multi-tool analysis (binary, SAST, dependencies)       │
│ • Correlate findings across tools                                   │
│ • Classify by severity and exploitability                          │
│ • Generate reports and recommendations                              │
└──────────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────────┐
│ SECURITY ANALYSIS PLUGIN (Phases 1-3)                               │
├──────────────────────────────────────────────────────────────────────┤
│ Phase 1: Dependency Scanning (Easy - 1-2 days)                      │
│  • scan_dependencies() → Identify vulnerable packages               │
│  • check_dependency_against_cves() → CVE lookup                    │
│  • DependencyScan ORM stores results                                │
│                                                                      │
│ Phase 2: SAST (Static Code Analysis) (Medium - 3-5 days)           │
│  • analyze_code() → Find code vulnerabilities                      │
│  • scan_code_for_patterns() → Custom patterns                      │
│  • correlate_code_to_cves() → Link to known CVEs                  │
│  • SASTFinding ORM stores results                                   │
│                                                                      │
│ Phase 3: Binary + ROP + Fuzz (Medium - 5-10 days)                 │
│  • analyze_binary() → Reverse engineering                          │
│  • find_rop_gadgets() → Exploitation capability                    │
│  • detect_fuzzable_functions() → Buffer overflows                  │
│  • run_fuzz_campaign() → Auto-trigger crashes                      │
│  • BinaryAnalysis, FuzzTestRun, FuzzCrash ORM models               │
└──────────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────────┐
│ BRAINCELL DATA WAREHOUSE                                             │
├──────────────────────────────────────────────────────────────────────┤
│ Persistent Storage:                                                  │
│ • PostgreSQL → All analysis findings, scan history                 │
│ • Weaviate → Vector search for similar vulnerabilities             │
│ • Redis → Cache, message queue for long-running tasks              │
│                                                                      │
│ Cells Used:                                                          │
│ • analysis/ → DependencyScan, SASTFinding, BinaryAnalysis          │
│ • threats/ → Link findings to known threat actors                  │
│ • incidents/ → Create incident from critical findings              │
│ • iocs/ → Track indicators (CVE IDs, package hashes)              │
└──────────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────────┐
│ REPORTING & ALERTING                                                 │
├──────────────────────────────────────────────────────────────────────┤
│ • Daily vulnerability report (email, Slack, webhook)               │
│ • Exploitability ranking (high/medium/low)                         │
│ • Blast radius calculation (affected repos, downstream)            │
│ • Remediation recommendations                                       │
│ • Links to CVE details, patch info, proof-of-concepts              │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Agent Workflow: Step-by-Step

### Phase 1: Repository Discovery & Prioritization

```python
# AGENT TASK 1: Discover top 100 repos to scan

@mcp.tool()
async def discover_top_github_repos(
    limit: int = 100,
    min_stars: int = 1000,
    languages: list[str] = ["python", "javascript", "go", "rust", "c", "cpp"]
) -> dict:
    """
    Use GitHub API to find most-used repositories by:
    • Stars (popularity)
    • Forks (adoption)
    • Recent activity (actively maintained)
    • Language diversity (different ecosystems)
    
    Returns:
    {
        "repos": [
            {
                "owner": "kubernetes",
                "repo": "kubernetes",
                "url": "https://github.com/kubernetes/kubernetes",
                "stars": 105000,
                "forks": 38000,
                "language": "go",
                "last_commit": "2026-08-03",
                "priority": 1  # High (active, widely used)
            },
            ...
        ],
        "total": 100,
        "estimated_scan_time": "14400 seconds"  # 4 hours
    }
    """
    # Implementation uses PyGithub or github3.py
    # Filters by language, min stars, recent activity
```

### Phase 2: Dependency Scanning (Fastest, Widest Coverage)

```python
# AGENT TASK 2: Scan all dependencies in top 100 repos

@mcp.tool()
async def scan_repo_dependencies(
    repo_owner: str,
    repo_name: str,
    package_managers: list[str] = ["pip", "npm", "cargo", "go.mod", "maven"]
) -> dict:
    """
    For each repo:
    1. Clone/download repository
    2. Detect package manager files (requirements.txt, package.json, etc.)
    3. Extract all dependencies (including transitive)
    4. Check against vulnerability databases:
       - NVD (National Vulnerability Database)
       - Safety for Python
       - npm audit database
       - Trivy vulnerability database
    5. Store findings in BrainCell
    
    Returns:
    {
        "repo": "kubernetes/kubernetes",
        "scan_type": "dependency",
        "vulnerabilities": [
            {
                "package": "etcd",
                "version": "3.4.0",
                "vulnerability": "CVE-2021-21240",
                "severity": "high",
                "fix_version": "3.4.1",
                "cwe": "CWE-327",  # Inadequate encryption
                "description": "Incorrect access control in etcd..."
            },
            ...
        ],
        "total_found": 7,
        "critical_count": 2,
        "high_count": 5,
        "scan_timestamp": "2026-08-03T14:30:00Z"
    }
    """
```

### Phase 3: Static Code Analysis (SAST)

```python
# AGENT TASK 3: Run SAST on discovered vulnerabilities

@mcp.tool()
async def analyze_vulnerable_code_paths(
    repo_owner: str,
    repo_name: str,
    vulnerable_modules: list[str],  # Modules from dependency scan
    analysis_depth: str = "targeted"  # "quick", "targeted", "deep"
) -> dict:
    """
    For critical dependencies found in Phase 2:
    1. Locate where dependency is used in code
    2. Analyze data flow from user input to vulnerable function
    3. Determine if vulnerability is actually exploitable
    4. Find all call sites that could trigger vulnerability
    
    Uses Semgrep with rules for:
    • CWE-327 (weak crypto)
    • CWE-434 (unsafe file upload)
    • CWE-502 (deserialization)
    • CWE-89 (SQL injection)
    • CWE-78 (command injection)
    
    Returns:
    {
        "repo": "kubernetes/kubernetes",
        "scan_type": "sast",
        "vulnerable_patterns": [
            {
                "cwe": "CWE-327",
                "file": "pkg/util/crypto.go",
                "line": 42,
                "pattern": "md5.New()",  # Weak hash algorithm
                "severity": "high",
                "why_risky": "MD5 is cryptographically broken",
                "affected_functions": ["ValidateSignature", "VerifyHash"],
                "potential_impact": "Signature spoofing, hash collision attacks"
            },
            ...
        ],
        "exploitable_findings": 3,
        "non_exploitable": 2,
        "requires_authentication": ["CVE-2021-240"]
    }
    """
```

### Phase 4: Binary Analysis & Exploitation Testing (Deep Dive)

```python
# AGENT TASK 4: Binary analysis for high-risk compiled binaries

@mcp.tool()
async def analyze_vulnerability_exploitability(
    repo_owner: str,
    repo_name: str,
    cve_ids: list[str],  # High-risk CVEs from phases 2-3
    build_binaries: bool = True  # Compile repo to test
) -> dict:
    """
    For compiled languages (Go, Rust, C/C++) with critical vulnerabilities:
    1. Download source code
    2. Build binaries locally
    3. Run binary analysis (Radare2):
       - Find vulnerable functions in compiled code
       - Check if ASLR/DEP/stack canaries in place
    4. Detect ROP gadgets available
    5. Run fuzzing on vulnerable functions
    6. Measure exploitability
    
    Returns:
    {
        "repo": "openssl/openssl",
        "cve": "CVE-2021-3711",  # OpenSSL NULL pointer dereference
        "binary_analysis": {
            "vulnerable_function": "X509_get_pubkey",
            "protection_status": {
                "aslr": "enabled",
                "dep": "enabled",
                "stack_canary": "enabled"
            },
            "rop_gadgets_available": 847,
            "can_bypass_protections": True,
            "estimated_difficulty": "moderate"
        },
        "fuzzing_results": {
            "crashes_found": 3,
            "exploitable_crashes": 2,
            "time_to_crash": 45,  # seconds
            "crash_reproducibility": 0.95
        },
        "severity": "critical",
        "exploitability": "high",
        "proof_of_concept": "available_on_exploit_db"
    }
    """
```

### Phase 5: Correlation & Risk Assessment

```python
# AGENT TASK 5: Correlate findings and calculate risk

@mcp.tool()
async def correlate_and_rank_vulnerabilities(
    repo_owner: str,
    repo_name: str,
    all_findings: dict  # Results from phases 2-4
) -> dict:
    """
    Consolidate all findings and create unified risk assessment:
    1. Deduplicate findings (same CVE found by multiple tools)
    2. Calculate blast radius:
       - How many downstream repos depend on this?
       - How widely used is this codebase?
    3. Determine exploitability:
       - Is exploit public? (check ExploitDB, 0day.today)
       - Active exploit in the wild? (check threat feeds)
       - Requires special conditions? (auth, network access)
    4. Identify affected users:
       - Who uses this repo? (GitHub dependents API)
       - What do they use it for? (critical vs optional)
    5. Rank by urgency:
       - Critical exploitable vulnerabilities = immediate
       - High severity but requires auth = 24-48 hours
       - Low severity = backlog
    
    Returns:
    {
        "repo": "kubernetes/kubernetes",
        "total_vulnerabilities": 12,
        "critical_exploitable": 2,
        "high_risk": 5,
        "medium_risk": 4,
        "low_risk": 1,
        "blast_radius": {
            "direct_dependents": 847,  # Repos depending on this
            "indirect_dependents": 12043,  # Transitively dependent
            "estimated_users_affected": 450000
        },
        "top_vulnerabilities": [
            {
                "rank": 1,
                "cve": "CVE-2021-3711",
                "severity": "critical",
                "exploitability": "high",
                "public_exploit": True,
                "active_exploitation": False,
                "days_until_critical": 0,
                "recommendation": "IMMEDIATE PATCH - Public exploit available"
            },
            {
                "rank": 2,
                "cve": "CVE-2021-44228",
                "severity": "critical",
                "exploitability": "critical",
                "public_exploit": True,
                "active_exploitation": True,
                "days_until_critical": 0,
                "recommendation": "EMERGENCY - Active exploitation in the wild"
            }
        ]
    }
    """
```

### Phase 6: Reporting & Alerting

```python
# AGENT TASK 6: Generate reports and send alerts

@mcp.tool()
async def generate_daily_vulnerability_report(
    scan_date: str,
    limit: int = 100
) -> dict:
    """
    Create comprehensive daily report of all vulnerabilities found:
    1. Summary statistics
    2. Critical vulnerabilities requiring immediate action
    3. High-risk vulnerabilities with mitigation steps
    4. New vulnerabilities discovered in this scan
    5. Vulnerability trends (increasing/decreasing)
    6. Recommendations for each repo owner
    7. Links to patches, CVE details, proof-of-concepts
    
    Returns:
    {
        "report_date": "2026-08-03",
        "report_type": "daily_vulnerability_summary",
        "repos_scanned": 100,
        "total_vulnerabilities": 487,
        "breakdown": {
            "critical": 8,
            "high": 47,
            "medium": 156,
            "low": 276
        },
        "new_vulnerabilities_today": 12,
        "critical_section": [
            {
                "repo": "kubernetes/kubernetes",
                "cve": "CVE-2021-3711",
                "title": "NULL pointer dereference in X509 certificate handling",
                "cvss_score": 9.8,
                "impact": "Remote Code Execution",
                "affected_version": "< 1.21.0",
                "patch_available": True,
                "patch_link": "https://github.com/kubernetes/kubernetes/releases/tag/v1.21.0",
                "workaround": "Disable X509 certificate parsing (not recommended)",
                "recommendation": "Upgrade to v1.21.0 immediately"
            }
        ],
        "blast_radius_summary": {
            "repos_with_critical_vulns": 8,
            "direct_dependents_affected": 1247,
            "estimated_users_affected": "1.2 million"
        },
        "trends": {
            "vulnerabilities_resolved_this_week": 15,
            "new_vulnerabilities_this_week": 47,
            "net_change": "+32"
        }
    }
    """
```

---

## Implementation Timeline

### Week 1: Foundation (Phases 1-2)

**Day 1-2: Dependency Scanning Setup**
```
- Implement detect_package_managers() → Find all dependency files
- Implement extract_dependencies() → Parse and collect all packages
- Implement scan_dependencies() MCP tool
- Set up PostgreSQL schema for DependencyScan model
```

**Day 3-5: SAST Integration**
```
- Configure Semgrep rules for CWE patterns
- Implement analyze_code() MCP tool
- Wire to Bandit for Python, eslint for JavaScript
- Test on 10 sample repos
```

**Output**: Can scan top 20 repos for dependencies + code issues (4-6 hours)

### Week 2: Deep Analysis (Phases 3-4)

**Day 6-8: Binary Analysis**
```
- Set up Radare2 integration for compiled binaries
- Implement find_rop_gadgets() tool
- Create build infrastructure (Docker containers per language)
- Test on sample binaries
```

**Day 9-10: Fuzzing & Exploitation**
```
- Configure AFL++ for C/C++/Go binaries
- Implement run_fuzz_campaign() MCP tool
- Create crash analyzer
- Test end-to-end on sample vulnerability
```

**Output**: Can analyze compilable repos for exploitation capability (6-8 hours for 100 repos)

### Week 3: Automation & Reporting (Phases 5-6)

**Day 11-12: Correlation & Risk Scoring**
```
- Implement correlate_and_rank_vulnerabilities() tool
- Create blast radius calculator
- Wire to GitHub dependents API
- Set up threat feed integration
```

**Day 13-14: Reporting & Alerting**
```
- Implement generate_daily_vulnerability_report() tool
- Create Slack/email formatting
- Set up scheduled tasks (cron or APScheduler)
- Create dashboard (optional Grafana)
```

**Output**: Full end-to-end scanning pipeline ready for production

---

## Automation: Daily Scanning Workflow

### Scheduled Job (APScheduler or Kubernetes CronJob)

```python
from apscheduler.schedulers.background import BackgroundScheduler
from itl_braincell_sdk.cells.analysis import AnalysisService
from itl_braincell_mcp.tools import ScanningTools

scheduler = BackgroundScheduler()

@scheduler.scheduled_job('cron', hour=2, minute=0, max_instances=1)
async def daily_github_scan():
    """
    Runs every night at 2 AM UTC
    Scans top 100 repos and generates report by morning
    """
    
    print("[Agent] Starting daily GitHub vulnerability scan...")
    
    # Step 1: Discover repos (cached, updated weekly)
    repos = await ScanningTools.discover_top_github_repos(limit=100)
    print(f"[Agent] Scanning {len(repos['repos'])} repositories")
    
    findings_by_repo = {}
    
    # Step 2-4: Scan each repo
    for repo in repos['repos']:
        owner, name = repo['owner'], repo['repo']
        print(f"[Agent] Scanning {owner}/{name}...")
        
        # Phase 2: Dependency scan (fastest, always run)
        dep_findings = await ScanningTools.scan_repo_dependencies(owner, name)
        findings_by_repo[f"{owner}/{name}"] = {
            "dependencies": dep_findings
        }
        
        # Phase 3: SAST (if dependencies found)
        if dep_findings['total_found'] > 0:
            sast_findings = await ScanningTools.analyze_vulnerable_code_paths(
                owner, name,
                vulnerable_modules=dep_findings['vulnerabilities']
            )
            findings_by_repo[f"{owner}/{name}"]["sast"] = sast_findings
        
        # Phase 4: Binary analysis (only for critical + compiled languages)
        if dep_findings['critical_count'] > 0 and repo['language'] in ['go', 'rust', 'c', 'cpp']:
            binary_findings = await ScanningTools.analyze_vulnerability_exploitability(
                owner, name,
                cve_ids=[v['vulnerability'] for v in dep_findings['vulnerabilities']]
            )
            findings_by_repo[f"{owner}/{name}"]["binary"] = binary_findings
    
    # Step 5: Correlate findings
    print("[Agent] Correlating findings across all repos...")
    correlated = await ScanningTools.correlate_and_rank_vulnerabilities(
        findings_by_repo
    )
    
    # Step 6: Generate report
    print("[Agent] Generating daily report...")
    report = await ScanningTools.generate_daily_vulnerability_report(
        scan_date=datetime.now().isoformat()
    )
    
    # Step 7: Send alerts
    await send_report_to_slack(report)
    await send_report_via_email(report)
    
    # Step 8: Store in BrainCell for historical tracking
    await store_scan_results(report)
    
    print("[Agent] Daily scan complete!")

scheduler.start()
```

---

## Data Storage & Querying

### Example: Query vulnerabilities from last 30 days

```python
from braincell.cells.analysis.models import DependencyScan, SASTFinding
from sqlalchemy import and_, select

# Find all critical vulnerabilities in top repos
query = select(DependencyScan).where(
    and_(
        DependencyScan.severity == "critical",
        DependencyScan.created_at >= datetime.now() - timedelta(days=30)
    )
).order_by(DependencyScan.cvss_score.desc())

results = await db.execute(query)
critical_vulns = results.scalars().all()

print(f"Found {len(critical_vulns)} critical vulnerabilities in last 30 days")
for vuln in critical_vulns:
    print(f"  - {vuln.package} {vuln.cve}: {vuln.description}")
```

### Example: Track vulnerability trends

```python
# Compare vulnerability counts week-over-week
last_week = await analyze.get_weekly_vulnerability_summary(
    weeks_ago=1
)
this_week = await analyze.get_weekly_vulnerability_summary(
    weeks_ago=0
)

print(f"Last week: {last_week['total']} vulnerabilities")
print(f"This week: {this_week['total']} vulnerabilities")
print(f"Trend: {'+' if this_week['total'] > last_week['total'] else '-'}{abs(this_week['total'] - last_week['total'])}")
```

---

## Integration: Linking to Threat Intelligence

### Auto-populate IOCs and Threat Intel

When vulnerabilities are discovered:

```python
async def link_vuln_to_threats(vulnerability: dict):
    """
    When a vulnerability is discovered:
    1. Check if any threat actors are known to exploit it
    2. Add to IOCs cell (CVE ID, exploit hashes, C2 domains)
    3. Create incident if exploited in the wild
    """
    
    # Check if CVE has active exploits
    cve_id = vulnerability['cve']
    threat_data = await search_threat_feeds(cve_id)
    
    if threat_data['exploited_in_wild']:
        # Create HIGH priority incident
        incident = await incidents_cell.create(
            title=f"ACTIVE EXPLOITATION: {cve_id}",
            severity="critical",
            affected_repos=threat_data['known_targets'],
            threat_actor=threat_data['threat_actor'],
            ioc_list=threat_data['observed_iocs']
        )
        
        # Send alert to security team
        await send_alert_to_security_team(incident)
```

---

## Success Metrics

| Metric | Target | How to Measure |
|--------|--------|-----------------|
| **Scanning Coverage** | 100 repos/day | repos_scanned / 100 |
| **Vulnerability Detection** | 400+ vulns/day | total_vulnerabilities found |
| **False Positive Rate** | < 5% | manual_review_misclassifications / total |
| **Time to Report** | < 4 hours | report_generated_time - scan_start_time |
| **Critical Finding Response** | < 30 min | alert_sent_time - vulnerability_detected_time |
| **Exploitability Accuracy** | > 90% | correct_exploitability_assessments / total |

---

## Scaling Considerations

### Optimize for 1,000+ repos

```python
# Use parallel scanning with worker queue
async def scan_repos_in_parallel(repos: list, max_workers: int = 10):
    """
    Use asyncio.gather() for parallel scanning
    Run dependency + SAST in parallel
    Only run binary analysis for critical findings
    Cache results to avoid re-scanning unchanged repos
    """
    tasks = [scan_repo(r) for r in repos]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return results
```

### Cache Management

```python
# Don't re-scan unchanged repos
async def should_rescan_repo(owner: str, name: str) -> bool:
    """
    Check if repo has changed since last scan:
    1. Query last commit hash in BrainCell
    2. Compare with GitHub's current commit hash
    3. If same: skip scanning, use cached results
    4. If different: re-scan
    """
    last_scan = await db.get_last_scan(owner, name)
    current_commit = await github_api.get_latest_commit(owner, name)
    
    return last_scan.commit_hash != current_commit['sha']
```

---

## Deliverables Checklist

- [ ] **Phase 1: Dependency Scanning**
  - [ ] DependencyScan ORM model created
  - [ ] scan_dependencies() MCP tool implemented
  - [ ] Scans 100 repos successfully
  - [ ] Stores results in PostgreSQL

- [ ] **Phase 2: SAST Analysis**
  - [ ] SASTFinding ORM model created
  - [ ] analyze_code() MCP tool implemented
  - [ ] Integrates Semgrep + Bandit
  - [ ] Correlates code findings to dependency vulnerabilities

- [ ] **Phase 3: Binary Analysis**
  - [ ] BinaryAnalysis, FuzzTestRun ORM models created
  - [ ] find_rop_gadgets(), run_fuzz_campaign() tools
  - [ ] Works on compiled binaries (Go, Rust, C++)
  - [ ] Analyzes exploitability

- [ ] **Phase 5: Correlation**
  - [ ] Deduplicates findings across tools
  - [ ] Calculates blast radius
  - [ ] Ranks by exploitability and severity

- [ ] **Phase 6: Reporting**
  - [ ] Daily vulnerability report generated
  - [ ] Slack/email integration
  - [ ] Scheduled daily at 2 AM UTC
  - [ ] Links to CVE details, patches, PoCs

---

## Quick Start Commands

```bash
# Trigger first scan manually
python -m braincell.security.agent scan_github_repos --limit 10 --verbose

# View scan results
curl http://localhost:9504/api/security/scans/latest

# Query vulnerabilities
curl "http://localhost:9504/api/security/vulnerabilities?severity=critical&limit=20"

# Generate report for date range
curl "http://localhost:9504/api/security/report?start_date=2026-08-01&end_date=2026-08-03"
```

---

## Next Steps

1. **Implement Phase 1 (1-2 days)** → scan_dependencies() tool working
2. **Implement Phase 2 (3-5 days)** → analyze_code() tool correlating findings
3. **Implement Phase 3 (5-10 days)** → Binary analysis + fuzzing
4. **Implement Phases 5-6 (5-7 days)** → Reporting + scheduling
5. **Deploy and scale** → Run daily scans on 100+ repos

**Total Timeline**: 2-3 weeks to full production scanning pipeline

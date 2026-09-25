# Code Inspection & Taint Analysis Workflow

**Objective**: Deploy an AI agent that performs **deep code inspection and analysis** to discover logic vulnerabilities, data flow issues, and exploitable patterns by analyzing:
- **Entry points** (user input, network, files, environment)
- **Data flow** (taint analysis following user-controlled data)
- **Logic vulnerabilities** (race conditions, TOCTOU, logic flaws)
- **Function analysis** (each function's security properties)
- **Manipulation vectors** (what can be exploited)

**Output**: Detailed per-function vulnerability report saved to BrainCell cells
**Use Case**: Find vulnerabilities that static tools miss (logic flaws, complex data flows, business logic bugs)

---

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│ CODE INSPECTION AGENT (Deep Analysis)                               │
├──────────────────────────────────────────────────────────────────────┤
│ Responsibilities:                                                     │
│ • Parse code into AST (Abstract Syntax Tree)                        │
│ • Identify entry points (sources of user input)                     │
│ • Trace data flow (taint analysis)                                  │
│ • Detect logic vulnerabilities (race conditions, TOCTOU)            │
│ • Analyze function signatures and security properties               │
│ • Find manipulation vectors (what can attacker control)             │
│ • Generate line-by-line analysis with security annotations          │
│ • Save findings to CodeInspection and DataFlow cells                │
└──────────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────────┐
│ CODE ANALYSIS SERVICE (Layer 1: SDK)                                │
├──────────────────────────────────────────────────────────────────────┤
│ ORM Models:                                                           │
│ • CodeInspection → Line-by-line analysis results                   │
│ • DataFlowPath → Tracks data from source to sink                   │
│ • FunctionAnalysis → Per-function security properties               │
│ • LogicVulnerability → Logic flaws detected                        │
│ • EntryPoint → User input/network/file sources                     │
│ • ManipulationVector → Ways to exploit data flow                   │
│                                                                      │
│ Service Classes:                                                     │
│ • CodeInspectionService → AST parsing & analysis                  │
│ • TaintAnalysisService → Track data flow                           │
│ • LogicAnalysisService → Detect logic vulnerabilities              │
│ • VulnerabilityMapper → Link findings to CVEs/CWEs                 │
└──────────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────────┐
│ BRAINCELL CELLS (Layer 3: Plugin)                                   │
├──────────────────────────────────────────────────────────────────────┤
│ • code_inspection/ → Line-by-line code analysis                    │
│ • data_flow/ → Taint tracking results                              │
│ • logic_vulnerabilities/ → Logic flaw findings                     │
│ • function_analysis/ → Per-function security assessment             │
│ • entry_points/ → Sources of user-controlled data                  │
│ • manipulation_vectors/ → Exploitation paths                        │
│                                                                      │
│ Each cell provides:                                                  │
│ • REST endpoints for querying findings                             │
│ • Relationships to code locations                                   │
│ • Links to SAST findings & binary analysis                         │
│ • Remediation recommendations                                       │
└──────────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────────┐
│ BRAINCELL DATA WAREHOUSE                                             │
├──────────────────────────────────────────────────────────────────────┤
│ • PostgreSQL → All inspection results, history                     │
│ • Weaviate → Semantic search ("find functions handling auth")       │
│ • Redis → Cache AST parsing results                                 │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Core Concepts

### 1. Entry Points (Sources)

**Definition**: Functions or variables that accept untrusted, user-controlled data

```python
class EntryPoint(Base, TimestampMixin):
    """Source of user-controlled data"""
    __tablename__ = "entry_points"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Location
    file_path = Column(String, nullable=False)
    function_name = Column(String, nullable=False)
    line_number = Column(Integer, nullable=False)
    
    # What is it?
    entry_type = Column(String)  # "function_parameter", "http_request", "file_read", "network_socket", "env_var", "command_line"
    parameter_name = Column(String, nullable=True)
    data_type = Column(String)  # "string", "bytes", "int", "object"
    
    # Trust level
    is_validated = Column(Boolean)  # Does it validate input?
    validation_type = Column(String, nullable=True)  # "regex", "whitelist", "type_check"
    trust_score = Column(Float)  # 0.0 (untrusted) to 1.0 (trusted)
    
    # Risk
    severity = Column(String)  # "critical", "high", "medium", "low"
    description = Column(String)
```

**Examples**:
```python
# Python
def handle_request(user_input: str):  # ENTRY POINT: HTTP parameter
    query = f"SELECT * FROM users WHERE id={user_input}"  # Data flows to SQL sink
    
def process_file(filename: str):  # ENTRY POINT: Filename from user
    with open(filename) as f:  # Path traversal possible
        
os.system(f"ping {hostname}")  # ENTRY POINT: hostname from user
    # Command injection possible
```

### 2. Data Flow (Taint)

**Definition**: How user-controlled data flows through the program

```python
class DataFlowPath(Base, TimestampMixin):
    """Trace of data from source to potential sink"""
    __tablename__ = "data_flow_paths"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Flow identification
    source_entry_point_id = Column(ForeignKey("entry_points.id"))
    sink_function = Column(String)  # Dangerous function: os.system, SQL execute, etc.
    
    # Flow path (journey through code)
    path_hops = Column(JSON)  # List of function calls in the flow
    # Example: ["handle_request()" → "validate_input()" → "execute_query()" → "cursor.execute()"]
    
    # Analysis
    is_tainted = Column(Boolean)  # Does taint reach the sink?
    taint_percentage = Column(Float)  # 0-100% of function parameters are tainted
    protective_operations = Column(JSON)  # ["parameterized_query", "input_validation"]
    
    # Risk
    risk_level = Column(String)  # "critical", "high", "medium", "low"
    cwe_id = Column(String)  # CWE-89 (SQL Injection), CWE-78 (Command Injection)
    
    # Code locations
    flow_chain = Column(JSON)  # [{file, line, function, operation}]
```

**Example data flow**:
```
Entry Point: user_input (line 42, handle_request)
  ↓ (passed as argument)
validate_input(user_input) (line 44)
  ↓ (no modification, still tainted)
execute_query(query_string) (line 50)
  ↓ (used directly in string concatenation)
cursor.execute(query) (line 52) ← SINK (SQL Injection)
```

### 3. Logic Vulnerabilities

**Definition**: Flaws in program logic that enable exploitation

```python
class LogicVulnerability(Base, TimestampMixin):
    """Logic flaw that enables security compromise"""
    __tablename__ = "logic_vulnerabilities"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # What is the flaw?
    vulnerability_type = Column(String)  # "TOCTOU", "race_condition", "logic_bypass", "type_confusion", "integer_overflow"
    severity = Column(String)  # "critical", "high", "medium", "low"
    cwe_id = Column(String)  # CWE-362 (TOCTOU), CWE-190 (Integer Overflow)
    
    # Where is it?
    file_path = Column(String, nullable=False)
    start_line = Column(Integer)
    end_line = Column(Integer)
    function_name = Column(String)
    
    # Description
    description = Column(String)
    exploitation_scenario = Column(String)  # How would attacker exploit this?
    
    # Impact
    impact = Column(String)  # "authentication_bypass", "authorization_bypass", "data_corruption"
    confidence = Column(Float)  # 0.0-1.0, how certain is this a real vulnerability?
    
    # Code snippet
    vulnerable_code = Column(Text)
    proof_of_concept = Column(Text)
```

**Examples**:
```python
# TOCTOU (Time-of-Check-Time-of-Use)
if os.path.exists(file):  # Check: file exists
    # Attacker deletes/replaces file here
    with open(file) as f:  # Use: file is read
        data = f.read()

# Race Condition
if account.balance >= amount:  # Thread 1 checks
    # Context switch here
    if account.balance >= amount:  # Thread 2 checks (same result)
        account.balance -= amount  # Thread 1 deducts
        account.balance -= amount  # Thread 2 deducts (double withdrawal!)

# Logic Bypass
if user.role == "admin":
    grant_privilege()
elif user.role == "user":
    pass
# What if user.role is None? Privilege granted anyway!
```

### 4. Function Analysis

**Definition**: Security properties of each function

```python
class FunctionAnalysis(Base, TimestampMixin):
    """Security analysis of a single function"""
    __tablename__ = "function_analyses"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Function identification
    file_path = Column(String, nullable=False)
    function_name = Column(String, nullable=False)
    line_number = Column(Integer)
    
    # Function signature
    signature = Column(String)  # def process_user_input(data: str, validate: bool = False) -> str:
    parameters = Column(JSON)  # {data: {type: str, is_tainted: true}, validate: {type: bool, default: false}}
    return_type = Column(String)
    
    # Security properties
    accepts_user_input = Column(Boolean)
    propagates_taint = Column(Boolean)  # Does it pass taint to other functions?
    has_validation = Column(Boolean)
    validation_strength = Column(String)  # "weak", "moderate", "strong"
    
    # Dangerous operations
    dangerous_operations = Column(JSON)  # ["os.system", "eval", "pickle.loads"]
    network_access = Column(Boolean)
    file_access = Column(Boolean)
    database_access = Column(Boolean)
    
    # Complexity
    cyclomatic_complexity = Column(Integer)  # Higher = harder to analyze
    lines_of_code = Column(Integer)
    nesting_depth = Column(Integer)  # Deep nesting = harder to understand
    
    # Findings
    security_issues = Column(JSON)
    missing_checks = Column(JSON)  # ["input_validation", "bounds_checking"]
    
    # Recommendations
    recommendations = Column(JSON)
```

---

## Analysis Workflow: Step-by-Step

### Step 1: Parse Code into AST

```python
@mcp.tool()
async def parse_code_to_ast(
    file_path: str,
    language: str = "python"  # "python", "javascript", "go", "rust"
) -> dict:
    """
    Parse source code into Abstract Syntax Tree (AST)
    Extract: functions, parameters, operations, control flow
    
    Returns:
    {
        "file": "auth.py",
        "language": "python",
        "functions": [
            {
                "name": "authenticate",
                "line": 42,
                "signature": "def authenticate(username: str, password: str) -> bool",
                "parameters": [
                    {"name": "username", "type": "str", "line": 42},
                    {"name": "password", "type": "str", "line": 42}
                ],
                "operations": [
                    {"line": 43, "type": "assignment", "code": "user = db.query(username)"},
                    {"line": 44, "type": "comparison", "code": "if user.password == password:"}
                ],
                "dangerous_calls": [
                    {"line": 43, "function": "db.query", "risk": "SQL injection if username not sanitized"}
                ]
            }
        ],
        "ast_json": "..."  # Full AST for detailed analysis
    }
    """
```

### Step 2: Identify Entry Points

```python
@mcp.tool()
async def identify_entry_points(
    file_path: str,
    ast_data: dict
) -> dict:
    """
    Find all functions that accept user-controlled data:
    • HTTP parameters (Flask, Django, FastAPI)
    • File operations (open, read)
    • Network operations (socket, requests)
    • Environment variables
    • Command-line arguments
    • Function parameters (if called from entry point)
    
    Returns:
    {
        "entry_points": [
            {
                "function": "handle_request",
                "line": 42,
                "parameter": "user_input",
                "type": "http_parameter",
                "trust_score": 0.0,  # Untrusted
                "reason": "Directly from HTTP GET parameter"
            },
            {
                "function": "process_file",
                "line": 128,
                "parameter": "filename",
                "type": "file_operation",
                "trust_score": 0.1,
                "reason": "User can specify filename"
            }
        ],
        "total_entry_points": 5,
        "high_risk_count": 3
    }
    """
```

### Step 3: Perform Taint Analysis

```python
@mcp.tool()
async def trace_data_flow(
    file_path: str,
    entry_point_name: str,
    parameter_name: str
) -> dict:
    """
    Follow data from entry point through code to find:
    • Where it's used
    • If it's validated/sanitized
    • If it reaches a dangerous function (sink)
    
    Returns:
    {
        "source": {
            "function": "handle_request",
            "parameter": "user_id",
            "type": "http_parameter"
        },
        "flow_path": [
            {
                "step": 1,
                "function": "handle_request",
                "line": 42,
                "operation": "receive parameter",
                "tainted": True
            },
            {
                "step": 2,
                "function": "validate_id",
                "line": 50,
                "operation": "call validate_id(user_id)",
                "tainted": True,
                "reason": "No validation performed"
            },
            {
                "step": 3,
                "function": "validate_id",
                "line": 51,
                "operation": "return user_id",
                "tainted": True,
                "reason": "Passed through unmodified"
            },
            {
                "step": 4,
                "function": "get_user_data",
                "line": 60,
                "operation": "db.query(f'SELECT * FROM users WHERE id={user_id}')",
                "tainted": True,
                "vulnerability": "SQL Injection",
                "cwe": "CWE-89"
            }
        ],
        "sink_found": True,
        "vulnerability_type": "SQL Injection",
        "risk_level": "critical",
        "proof_of_concept": "curl 'http://app/user?id=1 OR 1=1'"
    }
    """
```

### Step 4: Detect Logic Vulnerabilities

```python
@mcp.tool()
async def analyze_logic_vulnerabilities(
    file_path: str,
    function_name: str = None
) -> dict:
    """
    Scan for logic flaws:
    • TOCTOU (time-of-check-time-of-use)
    • Race conditions (unsynchronized access)
    • Type confusion (int vs string)
    • Off-by-one errors
    • Unreachable code paths
    • Missing null checks
    
    Returns:
    {
        "vulnerabilities": [
            {
                "type": "TOCTOU",
                "file": "file_operations.py",
                "lines": [45, 48],
                "description": "File is checked for existence, then opened without locking",
                "code": [
                    "45: if os.path.exists(file):",
                    "48:     with open(file) as f:"
                ],
                "exploitation": "Attacker can replace file between check and use",
                "cwe": "CWE-362",
                "severity": "high"
            },
            {
                "type": "race_condition",
                "file": "account.py",
                "lines": [120, 122],
                "description": "Check-then-act without lock",
                "severity": "critical"
            }
        ],
        "total_found": 3,
        "critical_count": 1
    }
    """
```

### Step 5: Analyze Function Security

```python
@mcp.tool()
async def analyze_function_security(
    file_path: str,
    function_name: str
) -> dict:
    """
    Detailed security analysis of a single function:
    • What data does it accept?
    • What does it do with it?
    • What can go wrong?
    • How should it be fixed?
    
    Returns:
    {
        "function": "authenticate_user",
        "file": "auth.py",
        "line": 42,
        "signature": "def authenticate_user(username: str, password: str) -> bool",
        
        "security_assessment": {
            "accepts_user_input": True,
            "input_parameters": [
                {
                    "name": "username",
                    "type": "str",
                    "taint_risk": "high",
                    "validation": "none",
                    "recommendation": "Add length check and character whitelist"
                },
                {
                    "name": "password",
                    "type": "str",
                    "taint_risk": "medium",
                    "validation": "partial (length check only)",
                    "recommendation": "Use timing-safe comparison"
                }
            ],
            "dangerous_operations": [
                {
                    "line": 45,
                    "operation": "db.query(f'SELECT * FROM users WHERE username=\"{username}\"')",
                    "vulnerability": "SQL Injection",
                    "severity": "critical",
                    "fix": "Use parameterized query"
                },
                {
                    "line": 50,
                    "operation": "return password == user.password",
                    "vulnerability": "Timing attack",
                    "severity": "medium",
                    "fix": "Use secrets.compare_digest()"
                }
            ]
        },
        
        "complexity_metrics": {
            "cyclomatic_complexity": 4,
            "lines_of_code": 12,
            "nesting_depth": 2
        },
        
        "recommendations": [
            "Use parameterized SQL queries",
            "Implement timing-safe password comparison",
            "Add rate limiting for login attempts",
            "Log all authentication attempts",
            "Use prepared statements"
        ],
        
        "security_score": 2.5,  # Out of 10 (lower = worse)
        "pass_fail": "FAIL"
    }
    """
```

### Step 6: Generate Comprehensive Report

```python
@mcp.tool()
async def generate_code_inspection_report(
    file_path: str,
    save_to_braincell: bool = True
) -> dict:
    """
    Generate complete code inspection report:
    • Line-by-line analysis
    • Entry points identified
    • Data flows tracked
    • Vulnerabilities found
    • Function security scores
    • Remediation roadmap
    
    Returns:
    {
        "report_type": "code_inspection",
        "file": "auth.py",
        "analysis_timestamp": "2026-08-03T14:30:00Z",
        
        "summary": {
            "total_functions": 12,
            "functions_with_user_input": 8,
            "entry_points_identified": 5,
            "critical_vulnerabilities": 2,
            "high_vulnerabilities": 5,
            "overall_security_score": 3.2  # Out of 10
        },
        
        "line_by_line_analysis": [
            {
                "line": 1,
                "code": "import os",
                "analysis": "Standard library import",
                "risk": "none"
            },
            {
                "line": 42,
                "code": "def authenticate(username: str, password: str) -> bool:",
                "analysis": "Function accepts user input directly as parameters",
                "risk": "high",
                "recommendations": ["Validate length", "Validate character set"]
            },
            {
                "line": 45,
                "code": "    user = db.query(f'SELECT * FROM users WHERE username=\"{username}\"')",
                "analysis": "SQL injection vulnerability - username used in f-string",
                "risk": "critical",
                "vulnerability": "CWE-89 SQL Injection",
                "fix": "user = db.query('SELECT * FROM users WHERE username=?', (username,))"
            }
        ],
        
        "entry_points": [
            {
                "function": "authenticate",
                "parameter": "username",
                "type": "direct_parameter",
                "trust_score": 0.0,
                "vulnerabilities": ["SQL Injection", "Buffer Overflow"]
            }
        ],
        
        "data_flows": [
            {
                "source": "authenticate:username",
                "sink": "db.query:query_string",
                "vulnerability": "SQL Injection",
                "path": ["authenticate() → line 45 → db.query()"]
            }
        ],
        
        "logic_vulnerabilities": [
            {
                "type": "timing_attack",
                "location": "line 50",
                "description": "Direct password comparison allows timing attacks",
                "fix": "Use secrets.compare_digest()"
            }
        ],
        
        "function_scores": [
            {
                "function": "authenticate",
                "score": 1.5,
                "issues": ["SQL Injection", "Timing Attack", "No rate limiting"]
            },
            {
                "function": "validate_token",
                "score": 7.2,
                "issues": ["Missing expiration check"]
            }
        ],
        
        "remediation_roadmap": [
            {
                "priority": "critical",
                "issue": "SQL Injection in authenticate()",
                "line": 45,
                "fix_effort": "15 minutes",
                "fix": "Use parameterized query"
            }
        ]
    }
    """
```

---

## ORM Models for Code Inspection Cell

```python
# FILE: ITL.Braincell.SDK/src/itl_braincell_sdk/cells/code_inspection/models.py

from sqlalchemy import Column, String, Integer, Float, Boolean, Text, JSON, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid

from itl_braincell_sdk.core.models import Base, TimestampMixin

class CodeInspection(Base, TimestampMixin):
    """Line-by-line code inspection results"""
    __tablename__ = "code_inspections"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    repo_owner = Column(String, nullable=False)  # GitHub owner
    repo_name = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    
    # Inspection details
    total_lines = Column(Integer)
    total_functions = Column(Integer)
    language = Column(String)  # python, javascript, go, rust, c
    
    # Results
    critical_issues = Column(Integer, default=0)
    high_issues = Column(Integer, default=0)
    medium_issues = Column(Integer, default=0)
    low_issues = Column(Integer, default=0)
    
    # Analysis
    ast_json = Column(JSON)  # Full AST
    line_by_line = Column(JSON)  # [{line, code, analysis, risk}]
    
    # Security score
    security_score = Column(Float)  # 0.0-10.0
    pass_fail = Column(String)  # "PASS" or "FAIL"
    
    # Status
    analysis_status = Column(String, default="pending")  # pending, in_progress, completed, failed
    error_message = Column(Text, nullable=True)


class EntryPoint(Base, TimestampMixin):
    """Source of user-controlled data"""
    __tablename__ = "entry_points"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code_inspection_id = Column(ForeignKey("code_inspections.id"))
    
    file_path = Column(String, nullable=False)
    function_name = Column(String, nullable=False)
    line_number = Column(Integer, nullable=False)
    
    entry_type = Column(String)  # function_parameter, http_request, file_read, network_socket
    parameter_name = Column(String, nullable=True)
    data_type = Column(String)
    
    is_validated = Column(Boolean, default=False)
    validation_type = Column(String, nullable=True)
    trust_score = Column(Float)  # 0.0 = untrusted, 1.0 = trusted
    
    severity = Column(String)  # critical, high, medium, low
    description = Column(String)
    
    vulnerabilities = Column(JSON)  # [CWE-89, CWE-78, ...]


class DataFlowPath(Base, TimestampMixin):
    """Taint analysis - data flow from source to sink"""
    __tablename__ = "data_flow_paths"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code_inspection_id = Column(ForeignKey("code_inspections.id"))
    source_entry_point_id = Column(ForeignKey("entry_points.id"))
    
    sink_function = Column(String)  # Dangerous function being called
    sink_line = Column(Integer)
    
    # Flow path
    path_hops = Column(JSON)  # [{function, line, operation}]
    is_tainted = Column(Boolean)  # Does taint reach sink?
    taint_percentage = Column(Float)  # 0-100% of parameters tainted
    
    protective_operations = Column(JSON)  # [input_validation, parameterized_query]
    
    risk_level = Column(String)  # critical, high, medium, low
    cwe_id = Column(String)  # CWE-89, CWE-78
    vulnerability_type = Column(String)  # SQL Injection, Command Injection
    
    proof_of_concept = Column(Text)  # How to exploit


class LogicVulnerability(Base, TimestampMixin):
    """Logic flaws in code"""
    __tablename__ = "logic_vulnerabilities"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code_inspection_id = Column(ForeignKey("code_inspections.id"))
    
    vulnerability_type = Column(String)  # TOCTOU, race_condition, type_confusion, integer_overflow
    severity = Column(String)  # critical, high, medium, low
    cwe_id = Column(String)
    
    file_path = Column(String, nullable=False)
    start_line = Column(Integer)
    end_line = Column(Integer)
    function_name = Column(String)
    
    description = Column(String)
    vulnerable_code = Column(Text)
    exploitation_scenario = Column(String)
    
    impact = Column(String)  # authentication_bypass, data_corruption
    confidence = Column(Float)  # 0.0-1.0
    
    proof_of_concept = Column(Text)


class FunctionAnalysis(Base, TimestampMixin):
    """Security analysis of individual functions"""
    __tablename__ = "function_analyses"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code_inspection_id = Column(ForeignKey("code_inspections.id"))
    
    file_path = Column(String, nullable=False)
    function_name = Column(String, nullable=False)
    line_number = Column(Integer)
    
    signature = Column(String)
    return_type = Column(String)
    
    # Security properties
    accepts_user_input = Column(Boolean)
    propagates_taint = Column(Boolean)
    has_validation = Column(Boolean)
    validation_strength = Column(String)  # weak, moderate, strong
    
    # Dangerous operations
    dangerous_operations = Column(JSON)  # [os.system, eval, pickle.loads]
    network_access = Column(Boolean)
    file_access = Column(Boolean)
    database_access = Column(Boolean)
    
    # Complexity
    cyclomatic_complexity = Column(Integer)
    lines_of_code = Column(Integer)
    nesting_depth = Column(Integer)
    
    # Findings
    security_issues = Column(JSON)
    missing_checks = Column(JSON)
    
    # Score
    security_score = Column(Float)  # 0.0-10.0
    pass_fail = Column(String)  # PASS or FAIL
    
    # Recommendations
    recommendations = Column(JSON)


class ManipulationVector(Base, TimestampMixin):
    """Ways to exploit data flow"""
    __tablename__ = "manipulation_vectors"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    data_flow_path_id = Column(ForeignKey("data_flow_paths.id"))
    
    vector_type = Column(String)  # SQL Injection, Command Injection, Path Traversal
    attack_method = Column(String)
    
    payload_example = Column(String)
    expected_result = Column(String)
    
    difficulty = Column(String)  # trivial, easy, moderate, hard
    impact = Column(String)  # Read/write/execute capability
    
    mitigation = Column(String)
```

---

## Implementation: Code Inspection Cell

```python
# FILE: ITL.Braincell.Cells.Security/src/itl_braincell_cells_security/cells/code_inspection/cell.py

from itl_braincell_sdk.cells.base import MemoryCell
from fastapi import APIRouter

class CodeInspectionCell(MemoryCell):
    """Deep code inspection and taint analysis cell"""
    
    @property
    def name(self) -> str:
        return "code_inspection"
    
    @property
    def prefix(self) -> str:
        return "/api/code-inspection"
    
    def get_models(self) -> list:
        from .models import CodeInspection, EntryPoint, DataFlowPath, LogicVulnerability, FunctionAnalysis, ManipulationVector
        return [CodeInspection, EntryPoint, DataFlowPath, LogicVulnerability, FunctionAnalysis, ManipulationVector]
    
    def get_router(self) -> APIRouter:
        from .routes import router
        return router
    
    def register_mcp_tools(self, mcp) -> None:
        """Register all code inspection tools for Claude/Agents"""
        from itl_braincell_sdk.core.database import SyncSessionLocal
        from .service import CodeInspectionService
        
        @mcp.tool()
        async def inspect_code(file_path: str, language: str = "python") -> dict:
            """Perform complete code inspection and taint analysis"""
            service = CodeInspectionService(SyncSessionLocal())
            return await service.inspect_code(file_path, language)
        
        @mcp.tool()
        async def analyze_data_flow(file_path: str, entry_point: str, parameter: str) -> dict:
            """Trace data flow from entry point to sinks"""
            service = CodeInspectionService(SyncSessionLocal())
            return await service.analyze_data_flow(file_path, entry_point, parameter)
        
        @mcp.tool()
        async def find_logic_vulnerabilities(file_path: str) -> dict:
            """Detect logic flaws (TOCTOU, race conditions, etc.)"""
            service = CodeInspectionService(SyncSessionLocal())
            return await service.find_logic_vulnerabilities(file_path)
        
        @mcp.tool()
        async def analyze_function_security(file_path: str, function_name: str) -> dict:
            """Analyze single function for security issues"""
            service = CodeInspectionService(SyncSessionLocal())
            return await service.analyze_function_security(file_path, function_name)
        
        @mcp.tool()
        async def generate_inspection_report(file_path: str) -> dict:
            """Generate comprehensive code inspection report"""
            service = CodeInspectionService(SyncSessionLocal())
            return await service.generate_inspection_report(file_path)
```

---

## Service Implementation

```python
# FILE: ITL.Braincell.SDK/src/itl_braincell_sdk/services/code_inspection_service.py

import ast
import subprocess
from typing import Optional
from .models import CodeInspection, EntryPoint, DataFlowPath, LogicVulnerability

class CodeInspectionService:
    """Deep code analysis service"""
    
    def __init__(self, db):
        self.db = db
    
    async def inspect_code(self, file_path: str, language: str) -> dict:
        """Parse and analyze code"""
        with open(file_path, 'r') as f:
            code = f.read()
        
        if language == "python":
            tree = ast.parse(code)
            return self._analyze_python_ast(tree, file_path)
        elif language == "javascript":
            return await self._analyze_javascript(file_path, code)
        elif language == "go":
            return await self._analyze_go(file_path, code)
    
    def _analyze_python_ast(self, tree: ast.AST, file_path: str) -> dict:
        """Analyze Python AST for security issues"""
        functions = []
        entry_points = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_data = {
                    "name": node.name,
                    "line": node.lineno,
                    "args": [arg.arg for arg in node.args.args],
                    "security_issues": self._analyze_function_node(node)
                }
                functions.append(func_data)
                
                # Check if it's an entry point
                if self._is_entry_point(node):
                    for arg in node.args.args:
                        entry_points.append({
                            "function": node.name,
                            "parameter": arg.arg,
                            "line": node.lineno,
                            "type": "function_parameter"
                        })
        
        return {
            "file": file_path,
            "functions": functions,
            "entry_points": entry_points,
            "total_functions": len(functions),
            "entry_point_count": len(entry_points)
        }
    
    def _analyze_function_node(self, node: ast.FunctionDef) -> list:
        """Find security issues in function"""
        issues = []
        
        for child in ast.walk(node):
            # Find SQL queries
            if isinstance(child, ast.JoinedStr):  # f-string
                issues.append({
                    "type": "SQL Injection risk",
                    "line": child.lineno,
                    "reason": "f-string used (possible injection)"
                })
            
            # Find os.system calls
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr == "system":
                        issues.append({
                            "type": "Command Injection",
                            "line": child.lineno,
                            "reason": "os.system() allows command injection"
                        })
        
        return issues
    
    def _is_entry_point(self, node: ast.FunctionDef) -> bool:
        """Check if function accepts external input"""
        entry_point_names = ["handle_request", "process_input", "handle_data", "main"]
        return node.name in entry_point_names or node.name.startswith("handle_")
    
    async def analyze_data_flow(self, file_path: str, entry_point: str, parameter: str) -> dict:
        """Trace how data flows through program"""
        # This is complex - would use Pyt or similar library
        # For now, return structure
        return {
            "source": {"function": entry_point, "parameter": parameter},
            "sinks": [],  # Where does data go?
            "is_sanitized": False,
            "vulnerabilities": []
        }
    
    async def find_logic_vulnerabilities(self, file_path: str) -> dict:
        """Detect logic flaws"""
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        vulnerabilities = []
        
        for i, line in enumerate(lines):
            # Check for TOCTOU pattern
            if "os.path.exists" in line:
                # Look ahead for file operations
                for j in range(i+1, min(i+10, len(lines))):
                    if "open(" in lines[j]:
                        vulnerabilities.append({
                            "type": "TOCTOU",
                            "lines": [i+1, j+1],
                            "severity": "high"
                        })
                        break
        
        return {"vulnerabilities": vulnerabilities}
    
    async def analyze_function_security(self, file_path: str, function_name: str) -> dict:
        """Analyze single function"""
        return {
            "function": function_name,
            "security_score": 5.0,
            "issues": [],
            "recommendations": []
        }
    
    async def generate_inspection_report(self, file_path: str) -> dict:
        """Full inspection report"""
        return {
            "file": file_path,
            "summary": {},
            "findings": []
        }
```

---

## Workflow Integration

### Store Results in BrainCell

```python
async def save_inspection_to_braincell(
    inspection_result: dict,
    repo_owner: str,
    repo_name: str
):
    """Save code inspection results to BrainCell cells"""
    
    # Save main inspection
    code_inspection = CodeInspection(
        repo_owner=repo_owner,
        repo_name=repo_name,
        file_path=inspection_result['file'],
        total_lines=len(inspection_result.get('code', '')),
        total_functions=len(inspection_result['functions']),
        critical_issues=inspection_result['critical_count'],
        ast_json=inspection_result['ast'],
        security_score=inspection_result['security_score']
    )
    db.add(code_inspection)
    await db.commit()
    
    # Save entry points
    for ep in inspection_result['entry_points']:
        entry_point = EntryPoint(
            code_inspection_id=code_inspection.id,
            file_path=ep['file'],
            function_name=ep['function'],
            line_number=ep['line'],
            parameter_name=ep['parameter'],
            trust_score=ep['trust_score'],
            severity=ep['severity']
        )
        db.add(entry_point)
    
    # Save data flows
    for df in inspection_result['data_flows']:
        data_flow = DataFlowPath(
            code_inspection_id=code_inspection.id,
            sink_function=df['sink'],
            is_tainted=df['is_tainted'],
            risk_level=df['risk'],
            cwe_id=df['cwe'],
            proof_of_concept=df['poc']
        )
        db.add(data_flow)
    
    # Save logic vulnerabilities
    for lv in inspection_result['logic_vulnerabilities']:
        logic_vuln = LogicVulnerability(
            code_inspection_id=code_inspection.id,
            vulnerability_type=lv['type'],
            severity=lv['severity'],
            file_path=lv['file'],
            start_line=lv['start'],
            end_line=lv['end'],
            description=lv['description'],
            cwe_id=lv['cwe']
        )
        db.add(logic_vuln)
    
    await db.commit()
    
    return code_inspection.id
```

### Query Results from BrainCell

```python
# Find all critical vulnerabilities in a repo
async def get_critical_findings(repo_owner: str, repo_name: str) -> list:
    """Get all critical issues in repo"""
    query = select(CodeInspection).where(
        (CodeInspection.repo_owner == repo_owner) &
        (CodeInspection.repo_name == repo_name) &
        (CodeInspection.critical_issues > 0)
    )
    
    result = await db.execute(query)
    return result.scalars().all()

# Find all SQL injection vulnerabilities
async def find_sql_injection_sinks() -> list:
    """Find all data flows leading to SQL injection"""
    query = select(DataFlowPath).where(
        (DataFlowPath.vulnerability_type == "SQL Injection") &
        (DataFlowPath.is_tainted == True)
    )
    
    result = await db.execute(query)
    return result.scalars().all()

# Get functions with highest risk
async def get_high_risk_functions() -> list:
    """Functions with security issues"""
    query = select(FunctionAnalysis).where(
        FunctionAnalysis.security_score < 4.0
    ).order_by(FunctionAnalysis.security_score.asc())
    
    result = await db.execute(query)
    return result.scalars().all()
```

---

## Success Metrics

| Metric | Target | Impact |
|--------|--------|--------|
| **Entry Points Found** | 100% coverage | Identifies all user input sources |
| **Logic Vulnerabilities** | > 90% detection | Catches race conditions, TOCTOU, bypass logic |
| **Data Flow Accuracy** | > 95% | Correctly traces taint through code |
| **False Positive Rate** | < 5% | Not flagging secure code |
| **Remediation Clarity** | 100% have fixes | Each finding has clear remediation |
| **Time to Analyze** | < 30 sec per 1000 LOC | Fast enough for daily scanning |

---

## Deliverables Checklist

- [ ] **ORM Models Created**
  - [ ] CodeInspection model
  - [ ] EntryPoint model
  - [ ] DataFlowPath model
  - [ ] LogicVulnerability model
  - [ ] FunctionAnalysis model
  - [ ] ManipulationVector model

- [ ] **Service Classes Implemented**
  - [ ] CodeInspectionService
  - [ ] TaintAnalysisService
  - [ ] LogicAnalysisService

- [ ] **MCP Tools Exposed**
  - [ ] inspect_code()
  - [ ] analyze_data_flow()
  - [ ] find_logic_vulnerabilities()
  - [ ] analyze_function_security()
  - [ ] generate_inspection_report()

- [ ] **Cell Implemented**
  - [ ] code_inspection/ cell
  - [ ] Routes for querying findings
  - [ ] Integration with other cells (link to SAST, binary analysis)

- [ ] **Integration**
  - [ ] Link to existing analysis findings
  - [ ] Correlate with dependency scan results
  - [ ] Feed into kill chain analysis
  - [ ] Support daily scanning workflow

---

## Quick Start

```bash
# Inspect a single file
python -m braincell.security.code_inspection inspect_code --file auth.py --language python

# Get report
curl http://localhost:9504/api/code-inspection/report/auth.py

# Query entry points
curl "http://localhost:9504/api/code-inspection/entry-points?severity=critical"

# Find SQL injection data flows
curl "http://localhost:9504/api/code-inspection/data-flows?vulnerability=SQL%20Injection"
```

---

## Next Steps

1. Implement ORM models in SDK
2. Create CodeInspectionService with basic AST parsing
3. Build code_inspection cell with routes
4. Implement MCP tool wrappers
5. Integrate with GitHub scanning workflow
6. Add support for multiple languages (JavaScript, Go, Rust)
7. Enhance taint analysis with dataflow tracking libraries

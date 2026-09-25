# ITL.Braincell.Cells — Plugin Packages

All cell collection plugins for the ITL BrainCell platform.

## Plugins

| Folder | Package | Cells | Status |
|--------|---------|-------|--------|
| **ITL.Braincell.Cells.Security** | `itl-braincell-cells-security` | threats, incidents, iocs, intel_reports, kill_chains, vuln_reports, vuln_patches | ✅ In progress (threats done) |
| **ITL.Braincell.Cells.Architecture** | `itl-braincell-cells-architecture` | architecture_notes, decisions, api_contracts, runbooks, references | 📋 Scaffolded |
| **ITL.Braincell.Cells.Codebase** | `itl-braincell-cells-codebase` | dependencies, versions, errors, research_questions | 📋 Scaffolded |
| **ITL.Braincell.Cells.Operations** | `itl-braincell-cells-operations` | tasks, jobs, persons, interactions, sessions | 📋 Scaffolded |

## Quick Start

### Install All Plugins (Local Development)

```bash
cd ITL.Braincell.Cells.Security && pip install -e .
cd ../ITL.Braincell.Cells.Architecture && pip install -e .
cd ../ITL.Braincell.Cells.Codebase && pip install -e .
cd ../ITL.Braincell.Cells.Operations && pip install -e .
```

Or use the convenience script:

```bash
# From ITL.Braincell.Cells folder
foreach ($plugin in @('Security', 'Architecture', 'Codebase', 'Operations')) {
  cd "ITL.Braincell.Cells.$plugin" && pip install -e . && cd ..
}
```

### Install Specific Plugins

```bash
cd ITL.Braincell.Cells.Security && pip install -e .
```

### Verify Installation

```python
from itl_braincell_sdk.cells import discover_cells
cells = discover_cells()
print([c.name for c in cells])
```

## Directory Structure

```
ITL.Braincell.Cells/
├── README.md                                    (this file)
├── ITL.Braincell.Cells.Security/
│   ├── README.md
│   ├── pyproject.toml
│   ├── .gitignore
│   └── src/itl_braincell_cells_security/
│       └── cells/
│           ├── __init__.py (SecurityPlugin)
│           ├── threats/
│           ├── incidents/
│           └── ...
├── ITL.Braincell.Cells.Architecture/
│   ├── README.md
│   ├── pyproject.toml
│   ├── .gitignore
│   └── src/itl_braincell_cells_architecture/
│       └── cells/
│           ├── __init__.py (ArchitecturePlugin)
│           ├── architecture_notes/
│           └── ...
├── ITL.Braincell.Cells.Codebase/
│   ├── README.md
│   ├── pyproject.toml
│   ├── .gitignore
│   └── src/itl_braincell_cells_codebase/
│       └── cells/
│           ├── __init__.py (CodebasePlugin)
│           ├── dependencies/
│           └── ...
└── ITL.Braincell.Cells.Operations/
    ├── README.md
    ├── pyproject.toml
    ├── .gitignore
    └── src/itl_braincell_cells_operations/
        └── cells/
            ├── __init__.py (OperationsPlugin)
            ├── tasks/
            └── ...
```

## Plugin Details

### Security Plugin (`ITL.Braincell.Cells.Security`)

7 cells for threat intelligence, incident tracking, and vulnerability management:
- **threats** ✅ — Threat actors and adversary profiles
- **incidents** 📋 — Security incident tracking
- **iocs** 📋 — Indicators of Compromise
- **intel_reports** 📋 — Threat intelligence reports
- **kill_chains** 📋 — Attack chains and TTP mappings
- **vuln_reports** 📋 — Vulnerability reports
- **vuln_patches** 📋 — Patch and remediation tracking

### Architecture Plugin (`ITL.Braincell.Cells.Architecture`)

5 cells for system design and operational procedures:
- **architecture_notes** — Component design and documentation
- **decisions** — Architecture Decision Records (ADRs)
- **api_contracts** — API specifications and OpenAPI contracts
- **runbooks** — Operational procedures
- **references** — Documentation links and references

### Codebase Plugin (`ITL.Braincell.Cells.Codebase`)

4 cells for code intelligence:
- **dependencies** — Software dependency tracking
- **versions** — Version and release management
- **errors** — Error and bug tracking
- **research_questions** — Research tasks

### Operations Plugin (`ITL.Braincell.Cells.Operations`)

5 cells for project management:
- **tasks** — Backlog items and work tracking
- **jobs** — Background job tracking
- **persons** — People and entity management
- **interactions** — Entity relationships
- **sessions** — User session tracking

## Development Workflow

### 1. Migrate Cells from SDK

Copy cell folders from `d:\repos\ITL.Braincell.SDK\src\itl_braincell_sdk\cells\<cellname>\` into the appropriate plugin:

```bash
# Example: migrate architecture_notes to Architecture plugin
cp -r d:\repos\ITL.Braincell.SDK\src\itl_braincell_sdk\cells\architecture_notes\ \
      d:\repos\ITL.Braincell.Cells\ITL.Braincell.Cells.Architecture\src\itl_braincell_cells_architecture\cells\
```

### 2. Update Imports

Change imports from SDK paths to local relative imports:

```python
# OLD (SDK)
from itl_braincell_sdk.cells.base import MemoryCell

# NEW (Plugin)
from itl_braincell_sdk.cells.base import MemoryCell  # Still from SDK
# (relative imports within the cell package)
```

### 3. Uncomment Plugin Registration

In each plugin's `cells/__init__.py`, uncomment the cell imports:

```python
# BEFORE
# from .architecture_notes.cell import cell as architecture_notes_cell

# AFTER
from .architecture_notes.cell import cell as architecture_notes_cell
```

### 4. Test Locally

```bash
cd ITL.Braincell.Cells.Architecture
pip install -e .
python -c "from itl_braincell_sdk.cells import discover_cells; print([c.name for c in discover_cells()])"
```

### 5. Verify in API

```bash
cd ../../ITL.BrainCell.Api
docker compose up -d
pytest  # Verify cells load
```

## Publishing

Each plugin is published independently to PyPI. See individual plugin's README for publishing instructions.

### GitFlow Strategy

- `develop` branch → TestPyPI (pre-release, e.g., v0.1.0rc1)
- `release/v*.*` branch → TestPyPI (release candidate)
- `main` branch + `v*.*.*` tag → PyPI (stable release)

Each plugin versions independently—no coordination needed.

## API Reference

Each cell exposes REST endpoints via FastAPI:

```
GET    /api/<cellname>/              # List all records
POST   /api/<cellname>/              # Create new record
GET    /api/<cellname>/{id}          # Get by ID
PUT    /api/<cellname>/{id}          # Update
DELETE /api/<cellname>/{id}          # Delete
```

MCP tools are also registered automatically for each cell.

## FAQ

**Q: Can plugins be used independently?**  
A: All plugins depend on `itl-braincell-sdk>=0.1.0`. You can install just the plugins you need.

**Q: Can I create my own plugin?**  
A: Yes. See the `itl-braincell-cells-examples` package in the SDK repo for a template.

**Q: How do I report issues?**  
A: Open issues in the respective plugin folder (or the SDK if it's core).

**Q: When will cells be migrated from the SDK?**  
A: Migration is in progress. See status in the table above.

## Links

- **BrainCell SDK:** `d:\repos\ITL.Braincell.SDK`
- **BrainCell API:** `d:\repos\ITL.BrainCell.Api`
- **BrainCell MCP:** `d:\repos\ITL.BrainCell.Mcp`
- **BrainCell Dashboard:** `d:\repos\ITL.BrainCell.Dashboard`

## License

MIT — Same as ITL.Braincell.SDK

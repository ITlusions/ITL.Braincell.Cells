# Migration Guide: Moving SDK Cells to Plugins

This guide explains how to extract cells from the SDK and organize them into separate plugin packages.

## Current SDK Cell Distribution (28 cells)

### Step 1: Identify Core vs Removable Cells

**Core cells (KEEP in SDK):**
- `notes` — Universal note storage
- `conversations` — Discussion history
- `snippets` — Code/text snippets
- `files_discussed` — File references

**Removable to plugins:**
- 24 cells → 4 plugin packages

---

## Plugin Organization Strategy

### 🔒 Plugin 1: Security & Threat Intelligence
**Package:** `itl-braincell-cells-security`
**Cells (7):**
- `threats` — Threat actors & TTPs
- `incidents` — Incident tracking
- `iocs` — Indicators of Compromise
- `intel_reports` — Intelligence reports
- `kill_chains` — Attack kill chains
- `vuln_reports` — Vulnerability reports
- `vuln_patches` — Security patches

**Entry point:**
```toml
[project.entry-points."itl_braincell_sdk.cell_plugins"]
security = "itl_braincell_cells_security.cells:plugin"
```

### 🏗️ Plugin 2: Architecture & Design
**Package:** `itl-braincell-cells-architecture`
**Cells (5):**
- `architecture_notes` — System component design
- `decisions` — Design decisions & ADRs
- `api_contracts` — API specifications
- `runbooks` — Operational procedures
- `references` — Reference materials

**Entry point:**
```toml
[project.entry-points."itl_braincell_sdk.cell_plugins"]
architecture = "itl_braincell_cells_architecture.cells:plugin"
```

### 📚 Plugin 3: Codebase Intelligence
**Package:** `itl-braincell-cells-codebase`
**Cells (4):**
- `dependencies` — Package/library tracking
- `versions` — Version & release tracking
- `errors` — Error & bug tracking
- `research_questions` — Research tasks

**Entry point:**
```toml
[project.entry-points."itl_braincell_sdk.cell_plugins"]
codebase = "itl_braincell_cells_codebase.cells:plugin"
```

### 📋 Plugin 4: Operations & Project Management
**Package:** `itl-braincell-cells-operations`
**Cells (5):**
- `tasks` — Backlog & work items
- `jobs` — Background job tracking
- `persons` — People/entities
- `interactions` — Entity relationships
- `sessions` — User sessions

**Entry point:**
```toml
[project.entry-points."itl_braincell_sdk.cell_plugins"]
operations = "itl_braincell_cells_operations.cells:plugin"
```

---

## Migration Steps

### For Each Plugin Package:

1. **Create package structure:**
   ```
   itl-braincell-cells-<name>/
   ├── pyproject.toml              (with entry point)
   ├── src/itl_braincell_cells_<name>/
   │   ├── __init__.py             (CellCollectionPlugin class)
   │   └── cells/
   │       ├── __init__.py         (export plugin instance)
   │       ├── cell1/
   │       │   ├── __init__.py
   │       │   ├── cell.py
   │       │   ├── model.py
   │       │   ├── schema.py
   │       │   └── routes.py
   │       └── cell2/
   │           └── ...
   ```

2. **Copy cell files from SDK:**
   - Copy `src/itl_braincell_sdk/cells/<cellname>/*` → `src/itl_braincell_cells_<name>/cells/<cellname>/`
   - Update imports: `itl_braincell_sdk.cells.<cellname>` → local relative imports

3. **Create plugin class in `cells/__init__.py`:**
   ```python
   from itl_braincell_sdk.cells.plugins import CellCollectionPlugin
   from .cell1.cell import cell as cell1
   from .cell2.cell import cell as cell2
   
   class ArchitecturePlugin(CellCollectionPlugin):
       @property
       def name(self) -> str:
           return "architecture"
       
       def get_cells(self):
           return [cell1, cell2]
   
   plugin = ArchitecturePlugin()
   ```

4. **Update `pyproject.toml`:**
   ```toml
   [project.entry-points."itl_braincell_sdk.cell_plugins"]
   architecture = "itl_braincell_cells_architecture.cells:plugin"
   ```

5. **Remove cells from SDK:**
   - Delete `src/itl_braincell_sdk/cells/<cellname>/` directories
   - Update SDK `cells/__init__.py` if needed
   - Run tests to ensure SDK still works

6. **Install plugin locally:**
   ```bash
   cd itl-braincell-cells-<name>
   pip install -e .
   ```

7. **Update consuming services:**
   - `ITL.BrainCell.Api` — no changes needed (auto-discovers via entry points)
   - `ITL.BrainCell.Mcp` — no changes needed (auto-discovers via entry points)
   - `ITL.BrainCell.Dashboard` — no changes needed

---

## Benefits of This Organization

| Benefit | Impact |
|---------|--------|
| **Smaller SDK** | Faster installs, clearer core purpose |
| **Independent release cycles** | Security plugin can update without SDK release |
| **Optional installation** | Users only install plugins they need |
| **Easier to maintain** | Each plugin has focused responsibility |
| **Community contributions** | Anyone can create cell plugins |
| **Better versioning** | Each plugin can have its own version |

---

## Example: Install Just Security Cells

```bash
# Install only security plugin (not other plugins)
pip install itl-braincell-cells-security

# Start API — only loads:
# - 4 core SDK cells (notes, conversations, snippets, files_discussed)
# - 7 security cells (threats, incidents, iocs, ...)
# Total: 11 cells instead of 28
```

---

## Existing Example

See `d:\repos\itl-braincell-cells-security\` for a working security plugin template with the `threats` cell fully implemented.

---

## Summary

The plugin architecture allows you to:
1. Keep SDK lean (4 essential cells)
2. Distribute 24 cells across 4 focused plugins
3. Install plugins independently based on needs
4. Maintain each plugin with its own release cycle
5. Allow community to create additional plugins

Each plugin package is a standard Python package that publishes an entry point. Discovery happens automatically at API/MCP startup.

# ITL BrainCell Cells — Codebase Intelligence

A plugin package for BrainCell that provides codebase intelligence memory cells for tracking dependencies, versions, errors, and research.

## Included Cells

- **dependencies** — Software dependency tracking and CVE monitoring
- **versions** — Version and release tracking
- **errors** — Error and bug tracking
- **research_questions** — Research tasks and questions

## Installation

### Local Development
```bash
cd d:\repos\itl-braincell-cells-codebase
pip install -e .
```

### From PyPI
```bash
pip install itl-braincell-cells-codebase
```

After installation, cells are automatically discovered when the BrainCell API/MCP server starts.

## Usage

Each cell exposes REST endpoints and MCP tools for codebase intelligence queries.

## Cell Migration

Cells are being migrated from the SDK. Current status:
- [ ] dependencies
- [ ] versions
- [ ] errors
- [ ] research_questions

Copy cells from `d:\repos\ITL.Braincell.SDK\src\itl_braincell_sdk\cells\<cellname>\` and adapt imports to local structure.

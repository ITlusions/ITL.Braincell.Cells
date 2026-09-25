# ITL BrainCell Cells — Operations & Project Management

A plugin package for BrainCell that provides operations and project management cells for task tracking, jobs, persons, and team interactions.

## Included Cells

- **tasks** — Backlog items and work tracking
- **jobs** — Background job tracking
- **persons** — People and entity management
- **interactions** — Entity relationships and interactions
- **sessions** — User session tracking

## Installation

### Local Development
```bash
cd d:\repos\itl-braincell-cells-operations
pip install -e .
```

### From PyPI
```bash
pip install itl-braincell-cells-operations
```

After installation, cells are automatically discovered when the BrainCell API/MCP server starts.

## Usage

Each cell exposes REST endpoints and MCP tools for operations and project management queries.

## Cell Migration

Cells are being migrated from the SDK. Current status:
- [ ] tasks
- [ ] jobs
- [ ] persons
- [ ] interactions
- [ ] sessions

Copy cells from `d:\repos\ITL.Braincell.SDK\src\itl_braincell_sdk\cells\<cellname>\` and adapt imports to local structure.

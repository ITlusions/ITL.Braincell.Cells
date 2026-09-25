# ITL BrainCell Cells — Architecture & Design

A plugin package for BrainCell that provides architecture and design-focused memory cells for system design, decisions, and operational procedures.

## Included Cells

- **architecture_notes** — System component design and documentation
- **decisions** — Design decisions and Architecture Decision Records (ADRs)
- **api_contracts** — API specifications and OpenAPI contracts
- **runbooks** — Operational procedures and runbooks
- **references** — Reference materials and documentation links

## Installation

### Local Development
```bash
cd d:\repos\itl-braincell-cells-architecture
pip install -e .
```

### From PyPI
```bash
pip install itl-braincell-cells-architecture
```

After installation, cells are automatically discovered when the BrainCell API/MCP server starts.

## Usage

Each cell exposes REST endpoints and MCP tools for architecture and design queries.

## Cell Migration

Cells are being migrated from the SDK. Current status:
- [ ] architecture_notes
- [ ] decisions
- [ ] api_contracts
- [ ] runbooks
- [ ] references

Copy cells from `d:\repos\ITL.Braincell.SDK\src\itl_braincell_sdk\cells\<cellname>\` and adapt imports to local structure.

"""Architecture & Design cell collection plugin.

Contributes 5 architecture-focused cells:
- architecture_notes (system component design)
- decisions (design decisions & ADRs)
- api_contracts (API specifications)
- runbooks (operational procedures)
- references (reference materials)

The plugin instance is exported as `plugin` for entry-point discovery.
"""
from itl_braincell_sdk.cells.base import MemoryCell
from itl_braincell_sdk.cells.plugins import CellCollectionPlugin


class ArchitecturePlugin(CellCollectionPlugin):
    """Plugin that contributes architecture and design cells."""

    @property
    def name(self) -> str:
        return "architecture"

    @property
    def description(self) -> str:
        return "Architecture & Design cell collection"

    def get_cells(self) -> list[MemoryCell]:
        # TODO: Import cells as they are migrated from SDK
        # from .architecture_notes.cell import cell as architecture_notes_cell
        # from .decisions.cell import cell as decisions_cell
        # from .api_contracts.cell import cell as api_contracts_cell
        # from .runbooks.cell import cell as runbooks_cell
        # from .references.cell import cell as references_cell
        #
        # return [
        #     architecture_notes_cell,
        #     decisions_cell,
        #     api_contracts_cell,
        #     runbooks_cell,
        #     references_cell,
        # ]
        return []


plugin = ArchitecturePlugin()

__all__ = ["ArchitecturePlugin", "plugin"]

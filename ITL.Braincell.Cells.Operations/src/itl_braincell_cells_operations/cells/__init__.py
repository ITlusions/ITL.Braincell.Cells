"""Operations & Project Management cell collection plugin.

Contributes 5 operations-focused cells:
- tasks (backlog & work items)
- jobs (background job tracking)
- persons (people/entities)
- interactions (entity relationships)
- sessions (user sessions)

The plugin instance is exported as `plugin` for entry-point discovery.
"""
from itl_braincell_sdk.cells.base import MemoryCell
from itl_braincell_sdk.cells.plugins import CellCollectionPlugin


class OperationsPlugin(CellCollectionPlugin):
    """Plugin that contributes operations and project management cells."""

    @property
    def name(self) -> str:
        return "operations"

    @property
    def description(self) -> str:
        return "Operations & Project Management cell collection"

    def get_cells(self) -> list[MemoryCell]:
        # TODO: Import cells as they are migrated from SDK
        # from .tasks.cell import cell as tasks_cell
        # from .jobs.cell import cell as jobs_cell
        # from .persons.cell import cell as persons_cell
        # from .interactions.cell import cell as interactions_cell
        # from .sessions.cell import cell as sessions_cell
        #
        # return [
        #     tasks_cell,
        #     jobs_cell,
        #     persons_cell,
        #     interactions_cell,
        #     sessions_cell,
        # ]
        return []


plugin = OperationsPlugin()

__all__ = ["OperationsPlugin", "plugin"]

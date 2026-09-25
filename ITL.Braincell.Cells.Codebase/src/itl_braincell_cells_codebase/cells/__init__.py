"""Codebase Intelligence cell collection plugin.

Contributes 4 codebase intelligence cells:
- dependencies (package/library tracking)
- versions (version & release tracking)
- errors (error & bug tracking)
- research_questions (research tasks)

The plugin instance is exported as `plugin` for entry-point discovery.
"""
from itl_braincell_sdk.cells.base import MemoryCell
from itl_braincell_sdk.cells.plugins import CellCollectionPlugin


class CodebasePlugin(CellCollectionPlugin):
    """Plugin that contributes codebase intelligence cells."""

    @property
    def name(self) -> str:
        return "codebase"

    @property
    def description(self) -> str:
        return "Codebase Intelligence cell collection"

    def get_cells(self) -> list[MemoryCell]:
        # TODO: Import cells as they are migrated from SDK
        # from .dependencies.cell import cell as dependencies_cell
        # from .versions.cell import cell as versions_cell
        # from .errors.cell import cell as errors_cell
        # from .research_questions.cell import cell as research_questions_cell
        #
        # return [
        #     dependencies_cell,
        #     versions_cell,
        #     errors_cell,
        #     research_questions_cell,
        # ]
        return []


plugin = CodebasePlugin()

__all__ = ["CodebasePlugin", "plugin"]

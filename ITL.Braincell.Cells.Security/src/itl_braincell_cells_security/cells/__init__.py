"""Security & Threat Intelligence cell collection plugin.

Contributes 7 security-focused cells:
- threats (threat actors & TTPs)
- incidents (incident tracking)
- iocs (indicators of compromise)
- intel_reports (intelligence briefings)
- kill_chains (attack kill chains)
- vuln_reports (vulnerability reports)
- vuln_patches (security patches)

The plugin instance is exported as `plugin` for entry-point discovery.
"""
from itl_braincell_sdk.cells.base import MemoryCell
from itl_braincell_sdk.plugins.base import CellCollectionPlugin

from .threats.cell import cell as threats_cell
from .incidents.cell import cell as incidents_cell
from .iocs.cell import cell as iocs_cell
from .intel_reports.cell import cell as intel_reports_cell
from .kill_chains.cell import cell as kill_chains_cell
from .vuln_reports.cell import cell as vuln_reports_cell
from .vuln_patches.cell import cell as vuln_patches_cell


class SecurityPlugin(CellCollectionPlugin):
    """Plugin that contributes security and threat intelligence cells."""

    @property
    def name(self) -> str:
        return "security"

    @property
    def description(self) -> str:
        return "Security & Threat Intelligence cell collection"

    def get_cells(self) -> list[MemoryCell]:
        return [
            threats_cell,
            incidents_cell,
            iocs_cell,
            intel_reports_cell,
            kill_chains_cell,
            vuln_reports_cell,
            vuln_patches_cell,
        ]


plugin = SecurityPlugin()

__all__ = ["SecurityPlugin", "plugin"]

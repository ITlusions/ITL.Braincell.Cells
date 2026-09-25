"""Intel reports memory cell — TLP-marked threat intelligence briefings."""
from fastapi import APIRouter

from itl_braincell_sdk.cells.base import MemoryCell


class IntelReportsCell(MemoryCell):
    """Memory cell for threat intelligence reports — TLP-marked analysis and briefings."""

    @property
    def name(self) -> str:
        return "intel_reports"

    @property
    def prefix(self) -> str:
        return "/api/intel-reports"

    def get_router(self) -> APIRouter:
        from .routes import router
        return router

    def get_models(self) -> list:
        from .model import IntelReport
        return [IntelReport]

    def register_mcp_tools(self, mcp) -> None:
        from itl_braincell_sdk.core.database import SyncSessionLocal
        from .model import IntelReport

        @mcp.tool()
        async def intel_reports_search(query: str, limit: int = 10) -> dict:
            """Search threat intelligence reports by title or summary.

            Use when asked 'do we have a briefing on X?' or 'find intel
            reports about this threat actor/campaign'.
            """
            db = SyncSessionLocal()
            try:
                q = query.lower()
                rows = db.query(IntelReport).filter(
                    IntelReport.title.ilike(f"%{q}%") |
                    IntelReport.summary.ilike(f"%{q}%")
                ).limit(limit).all()
                return {"query": query, "count": len(rows), "results": [
                    {"id": str(r.id), "title": r.title, "summary": r.summary,
                     "tlp_level": r.tlp_level, "source": r.source, "analyst": r.analyst}
                    for r in rows
                ]}
            finally:
                db.close()

        @mcp.tool()
        async def intel_reports_save(
            title: str,
            summary: str | None = None,
            content: str | None = None,
            tlp_level: str | None = None,
            source: str | None = None,
            analyst: str | None = None,
            classification_level: str | None = None,
        ) -> dict:
            """Save an intelligence report/briefing to BrainCell memory.

            Use when documenting analysis, a threat briefing, or an intel
            product for future reference.
            tlp_level: WHITE / GREEN / AMBER / RED
            """
            db = SyncSessionLocal()
            try:
                report = IntelReport(
                    title=title,
                    summary=summary,
                    content=content,
                    tlp_level=tlp_level,
                    source=source,
                    analyst=analyst,
                    classification_level=classification_level,
                )
                db.add(report)
                db.commit()
                db.refresh(report)
                return {"status": "saved", "id": str(report.id), "title": report.title}
            finally:
                db.close()


cell = IntelReportsCell()

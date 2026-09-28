"""Vulnerability reports memory cell — CVEs and findings tracked to remediation."""
import os

from fastapi import APIRouter

from itl_braincell_sdk.cells.background import CellBackgroundTask
from itl_braincell_sdk.cells.base import MemoryCell


class VulnReportsCell(MemoryCell):
    """Memory cell for vulnerability reports — CVEs and findings, discovery to remediation."""

    @property
    def name(self) -> str:
        return "vuln_reports"

    @property
    def prefix(self) -> str:
        return "/api/vuln-reports"

    def get_router(self) -> APIRouter:
        from .routes import router
        return router

    def get_models(self) -> list:
        from .model import VulnReport
        return [VulnReport]

    def get_background_tasks(self) -> list[CellBackgroundTask]:
        """Periodically run AI triage over open vulnerability reports.

        Disabled by default. Enable with:
          BRAINCELL_VULN_REPORTS_AUTO_TRIAGE=1
          BRAINCELL_VULN_REPORTS_AUTO_TRIAGE_INTERVAL_SECONDS=900  (default 15m)
        """
        if os.environ.get("BRAINCELL_VULN_REPORTS_AUTO_TRIAGE", "").lower() not in ("1", "true", "yes"):
            return []

        interval = float(os.environ.get("BRAINCELL_VULN_REPORTS_AUTO_TRIAGE_INTERVAL_SECONDS", "900"))

        def _run_triage() -> None:
            from itl_braincell_sdk.core.database import SyncSessionLocal

            from .agent import VulnReportTriageAgent

            db = SyncSessionLocal()
            try:
                VulnReportTriageAgent(db).run()
            finally:
                db.close()

        return [
            CellBackgroundTask(
                name="vuln_reports.ai_triage",
                interval_seconds=interval,
                run=_run_triage,
            )
        ]

    def register_mcp_tools(self, mcp) -> None:
        from itl_braincell_sdk.core.database import SyncSessionLocal
        from .model import VulnReport

        @mcp.tool()
        async def vuln_reports_search(query: str, limit: int = 10) -> dict:
            """Search vulnerability reports by title, CVE ID, or affected component.

            Use when asked 'is this CVE tracked?', 'what's the status of this
            vulnerability?', or 'find findings affecting this component'.
            """
            db = SyncSessionLocal()
            try:
                q = query.lower()
                rows = db.query(VulnReport).filter(
                    VulnReport.title.ilike(f"%{q}%") |
                    VulnReport.cve_id.ilike(f"%{q}%") |
                    VulnReport.affected_component.ilike(f"%{q}%")
                ).limit(limit).all()
                return {"query": query, "count": len(rows), "results": [
                    {"id": str(r.id), "title": r.title, "cve_id": r.cve_id,
                     "cvss_score": r.cvss_score, "severity": r.severity, "status": r.status,
                     "affected_component": r.affected_component}
                    for r in rows
                ]}
            finally:
                db.close()

        @mcp.tool()
        async def vuln_reports_save(
            title: str,
            description: str | None = None,
            cve_id: str | None = None,
            cvss_score: float | None = None,
            severity: str | None = None,
            affected_component: str | None = None,
            affected_versions: list[str] | None = None,
            discovered_by: str | None = None,
        ) -> dict:
            """Save a vulnerability report/finding to BrainCell memory.

            Use when a CVE or security finding needs to be tracked from
            discovery through remediation.
            severity: critical / high / medium / low
            """
            db = SyncSessionLocal()
            try:
                report = VulnReport(
                    title=title,
                    description=description,
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    severity=severity,
                    affected_component=affected_component,
                    affected_versions=affected_versions or [],
                    discovered_by=discovered_by,
                    status="open",
                )
                db.add(report)
                db.commit()
                db.refresh(report)
                return {"status": "saved", "id": str(report.id), "title": report.title}
            finally:
                db.close()

        @mcp.tool()
        async def vuln_reports_ai_triage(batch_size: int = 25) -> dict:
            """Run AI-based triage over open vulnerability reports now.

            An LLM reviews each open finding's context (CVE, CVSS, affected
            component/versions, description) and decides whether to escalate
            it to `incidents`, flag it as needs_review, or leave it open. Use
            when asked to 'triage open vulnerabilities with AI' or 'run the
            vuln_reports triage agent'.
            """
            from .agent import VulnReportTriageAgent

            db = SyncSessionLocal()
            try:
                agent = VulnReportTriageAgent(db, batch_size=batch_size)
                return agent.run()
            finally:
                db.close()


cell = VulnReportsCell()

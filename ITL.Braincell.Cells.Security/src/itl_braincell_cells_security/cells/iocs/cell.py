"""IOCs memory cell — tracks indicators of compromise (IPs, domains, hashes, CVEs)."""
from fastapi import APIRouter

from itl_braincell_sdk.cells.base import MemoryCell


class IocsCell(MemoryCell):
    """Memory cell for indicators of compromise — IPs, domains, hashes, CVEs."""

    @property
    def name(self) -> str:
        return "iocs"

    @property
    def prefix(self) -> str:
        return "/api/iocs"

    def get_router(self) -> APIRouter:
        from .routes import router
        return router

    def get_models(self) -> list:
        from .model import IOC
        return [IOC]

    def register_mcp_tools(self, mcp) -> None:
        from itl_braincell_sdk.core.database import SyncSessionLocal
        from .model import IOC

        @mcp.tool()
        async def iocs_search(query: str, limit: int = 20) -> dict:
            """Search indicators of compromise by value, type, or context.

            Use when asked 'is this IP/domain/hash known?', 'do we have IOCs
            matching this CVE?', or 'have we seen this indicator before?'.
            """
            db = SyncSessionLocal()
            try:
                q = query.lower()
                rows = db.query(IOC).filter(
                    IOC.value.ilike(f"%{q}%") |
                    IOC.ioc_type.ilike(f"%{q}%") |
                    IOC.context.ilike(f"%{q}%")
                ).limit(limit).all()
                return {"query": query, "count": len(rows), "results": [
                    {"id": str(r.id), "ioc_type": r.ioc_type, "value": r.value,
                     "severity": r.severity, "status": r.status, "source": r.source,
                     "tags": r.tags}
                    for r in rows
                ]}
            finally:
                db.close()

        @mcp.tool()
        async def iocs_save(
            ioc_type: str,
            value: str,
            severity: str | None = None,
            source: str | None = None,
            context: str | None = None,
            tags: list[str] | None = None,
        ) -> dict:
            """Save an indicator of compromise to BrainCell memory.

            Use when identifying a malicious IP, domain, file hash, CVE, URL, or
            email that should be tracked for future correlation and detection.
            ioc_type: ip / domain / hash_md5 / hash_sha256 / cve / url / email
            severity: critical / high / medium / low
            """
            db = SyncSessionLocal()
            try:
                ioc = IOC(
                    ioc_type=ioc_type,
                    value=value,
                    severity=severity,
                    source=source,
                    context=context,
                    tags=tags or [],
                    status="active",
                )
                db.add(ioc)
                db.commit()
                db.refresh(ioc)
                return {"status": "saved", "id": str(ioc.id), "value": ioc.value}
            finally:
                db.close()


cell = IocsCell()

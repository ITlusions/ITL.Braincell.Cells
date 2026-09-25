"""Vuln patches memory cell — known-vulnerable code paired with patched equivalents."""
from fastapi import APIRouter

from itl_braincell_sdk.cells.base import MemoryCell


class VulnPatchesCell(MemoryCell):
    """Memory cell for vulnerable/patched code pairs — a learned remediation knowledge base."""

    @property
    def name(self) -> str:
        return "vuln_patches"

    @property
    def prefix(self) -> str:
        return "/api/vuln-patches"

    def get_router(self) -> APIRouter:
        from .routes import router
        return router

    def get_models(self) -> list:
        from .model import VulnPatch
        return [VulnPatch]

    def register_mcp_tools(self, mcp) -> None:
        from itl_braincell_sdk.core.database import SyncSessionLocal
        from .model import VulnPatch

        @mcp.tool()
        async def vuln_patches_search(query: str, limit: int = 10) -> dict:
            """Search vulnerable/patched code pairs by title, description, or category.

            Use when asked 'have we fixed this vulnerability pattern before?'
            or 'show an example patch for this vulnerability class'.
            """
            db = SyncSessionLocal()
            try:
                q = query.lower()
                rows = db.query(VulnPatch).filter(
                    VulnPatch.title.ilike(f"%{q}%") |
                    VulnPatch.description.ilike(f"%{q}%") |
                    VulnPatch.category.ilike(f"%{q}%")
                ).limit(limit).all()
                return {"query": query, "count": len(rows), "results": [
                    {"id": str(r.id), "title": r.title, "category": r.category,
                     "severity": r.severity, "language": r.language,
                     "vulnerable_code": r.vulnerable_code, "patched_code": r.patched_code}
                    for r in rows
                ]}
            finally:
                db.close()

        @mcp.tool()
        async def vuln_patches_save(
            title: str,
            description: str | None = None,
            vulnerable_code: str | None = None,
            patched_code: str | None = None,
            patch_explanation: str | None = None,
            language: str | None = None,
            category: str | None = None,
            severity: str | None = None,
        ) -> dict:
            """Save a vulnerable/patched code pair to BrainCell memory.

            Use when a security fix has been applied and the before/after
            code should be remembered as a reusable remediation example.
            category: sql_injection / xss / ssrf / path_traversal / ...
            severity: critical / high / medium / low
            """
            db = SyncSessionLocal()
            try:
                patch = VulnPatch(
                    title=title,
                    description=description,
                    vulnerable_code=vulnerable_code,
                    patched_code=patched_code,
                    patch_explanation=patch_explanation,
                    language=language,
                    category=category,
                    severity=severity,
                )
                db.add(patch)
                db.commit()
                db.refresh(patch)
                return {"status": "saved", "id": str(patch.id), "title": patch.title}
            finally:
                db.close()


cell = VulnPatchesCell()

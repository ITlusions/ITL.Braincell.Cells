"""Kill chains memory cell — ordered attack stage sequences (MITRE ATT&CK) per incident/actor."""
from fastapi import APIRouter

from itl_braincell_sdk.cells.base import MemoryCell


class KillChainsCell(MemoryCell):
    """Memory cell for attack kill chains — ordered MITRE ATT&CK stage sequences."""

    @property
    def name(self) -> str:
        return "kill_chains"

    @property
    def prefix(self) -> str:
        return "/api/kill-chains"

    def get_router(self) -> APIRouter:
        from .routes import router
        return router

    def get_models(self) -> list:
        from .model import KillChain
        return [KillChain]

    def register_mcp_tools(self, mcp) -> None:
        from itl_braincell_sdk.core.database import SyncSessionLocal
        from .model import KillChain

        @mcp.tool()
        async def kill_chains_search(query: str, limit: int = 10) -> dict:
            """Search attack kill chains by title, description, or threat actor.

            Use when asked 'what was the attack sequence for this incident?'
            or 'show the kill chain for this threat actor's campaign'.
            """
            db = SyncSessionLocal()
            try:
                q = query.lower()
                rows = db.query(KillChain).filter(
                    KillChain.title.ilike(f"%{q}%") |
                    KillChain.description.ilike(f"%{q}%") |
                    KillChain.threat_actor_name.ilike(f"%{q}%")
                ).limit(limit).all()
                return {"query": query, "count": len(rows), "results": [
                    {"id": str(r.id), "title": r.title, "threat_actor_name": r.threat_actor_name,
                     "status": r.status, "stages": r.stages}
                    for r in rows
                ]}
            finally:
                db.close()

        @mcp.tool()
        async def kill_chains_save(
            title: str,
            description: str | None = None,
            threat_actor_name: str | None = None,
            stages: list[dict] | None = None,
            incident_id: str | None = None,
        ) -> dict:
            """Save an attack kill chain to BrainCell memory.

            Use when documenting the ordered sequence of attack stages
            (recon, weaponize, deliver, exploit, install, C2, actions-on-objective)
            for an incident or threat actor campaign.
            stages: list of {"stage": str, "ttp_id": str, "description": str, "timestamp": str}
            """
            db = SyncSessionLocal()
            try:
                chain = KillChain(
                    title=title,
                    description=description,
                    threat_actor_name=threat_actor_name,
                    stages=stages or [],
                    incident_id=incident_id,
                    status="active",
                )
                db.add(chain)
                db.commit()
                db.refresh(chain)
                return {"status": "saved", "id": str(chain.id), "title": chain.title}
            finally:
                db.close()


cell = KillChainsCell()

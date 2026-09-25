"""Incidents memory cell — tracks security incidents, breaches, and investigations."""
from fastapi import APIRouter

from itl_braincell_sdk.cells.base import MemoryCell


class IncidentsCell(MemoryCell):
    """Memory cell for security incidents — breaches, attacks, events under investigation."""

    @property
    def name(self) -> str:
        return "incidents"

    @property
    def prefix(self) -> str:
        return "/api/incidents"

    def get_router(self) -> APIRouter:
        from .routes import router
        return router

    def get_models(self) -> list:
        from .model import SecurityIncident
        return [SecurityIncident]

    def register_mcp_tools(self, mcp) -> None:
        from itl_braincell_sdk.core.database import SyncSessionLocal
        from .model import SecurityIncident

        @mcp.tool()
        async def incidents_search(query: str, limit: int = 10) -> dict:
            """Search security incidents by title, description, or attack vector.

            Use when asked 'have we seen this attack before?', 'what incidents
            involve this threat actor?', or 'find incidents matching X'.
            """
            db = SyncSessionLocal()
            try:
                q = query.lower()
                rows = db.query(SecurityIncident).filter(
                    SecurityIncident.title.ilike(f"%{q}%") |
                    SecurityIncident.description.ilike(f"%{q}%") |
                    SecurityIncident.attack_vector.ilike(f"%{q}%")
                ).limit(limit).all()
                return {"query": query, "count": len(rows), "results": [
                    {"id": str(r.id), "title": r.title, "severity": r.severity,
                     "status": r.status, "attack_vector": r.attack_vector,
                     "threat_actor_name": r.threat_actor_name, "mitre_tactics": r.mitre_tactics}
                    for r in rows
                ]}
            finally:
                db.close()

        @mcp.tool()
        async def incidents_save(
            title: str,
            description: str | None = None,
            severity: str | None = None,
            attack_vector: str | None = None,
            threat_actor_name: str | None = None,
            mitre_tactics: list[str] | None = None,
            classification_level: str | None = None,
        ) -> dict:
            """Save a security incident to BrainCell memory.

            Use when a breach, attack, or suspicious event needs to be recorded
            for investigation and future correlation.
            severity: critical / high / medium / low
            mitre_tactics: list of MITRE ATT&CK tactic IDs
            """
            db = SyncSessionLocal()
            try:
                incident = SecurityIncident(
                    title=title,
                    description=description,
                    severity=severity,
                    attack_vector=attack_vector,
                    threat_actor_name=threat_actor_name,
                    mitre_tactics=mitre_tactics or [],
                    classification_level=classification_level,
                    status="open",
                )
                db.add(incident)
                db.commit()
                db.refresh(incident)
                return {"status": "saved", "id": str(incident.id), "title": incident.title}
            finally:
                db.close()


cell = IncidentsCell()

"""Threats memory cell — tracks threat actors, TTPs, and attribution intelligence."""
from fastapi import APIRouter

from itl_braincell_sdk.cells.base import MemoryCell


class ThreatsCell(MemoryCell):
    """Memory cell for threat actors — APTs, criminal groups, TTPs, MITRE ATT&CK mapping."""

    @property
    def name(self) -> str:
        return "threats"

    @property
    def prefix(self) -> str:
        return "/api/threats"

    def get_router(self) -> APIRouter:
        from .routes import router
        return router

    def get_models(self) -> list:
        from .model import ThreatActor
        return [ThreatActor]

    def get_weaviate_schema(self) -> dict | None:
        return {
            "name": "ThreatActor",
            "properties": [
                {"name": "name", "dataType": ["text"]},
                {"name": "classification", "dataType": ["string"]},
                {"name": "motivation", "dataType": ["string"]},
                {"name": "ttps", "dataType": ["text"]},
            ],
        }

    def on_startup(self, db, weaviate_service) -> dict:
        """Backfill: index any threat actors not yet present in Weaviate."""
        from .model import ThreatActor

        indexed, failed = 0, 0
        for actor in db.query(ThreatActor).all():
            ok = weaviate_service.index(
                "ThreatActor",
                str(actor.id),
                {
                    "name": actor.name,
                    "classification": actor.classification,
                    "motivation": actor.motivation,
                    "ttps": actor.ttps,
                },
            )
            indexed += 1 if ok else 0
            failed += 0 if ok else 1
        return {"synced": indexed, "failed": failed}

    def register_mcp_tools(self, mcp) -> None:
        from itl_braincell_sdk.core.database import SyncSessionLocal
        from .model import ThreatActor

        @mcp.tool()
        async def threats_search(query: str, limit: int = 10) -> dict:
            """Search known threat actors by name, alias, classification, motivation, or TTP.

            Use when asked 'who is behind this attack?', 'which APT uses T1566?',
            'do we know this threat actor?', or 'which groups target our sector?'.
            Returns threat actor profiles with TTPs and attribution metadata.
            """
            db = SyncSessionLocal()
            try:
                q = query.lower()
                rows = db.query(ThreatActor).filter(
                    ThreatActor.name.ilike(f"%{q}%") |
                    ThreatActor.classification.ilike(f"%{q}%") |
                    ThreatActor.motivation.ilike(f"%{q}%")
                ).limit(limit).all()
                return {"query": query, "count": len(rows), "results": [
                    {"id": str(r.id), "name": r.name, "aliases": r.aliases,
                     "classification": r.classification, "motivation": r.motivation,
                     "sophistication": r.sophistication, "ttps": r.ttps,
                     "origin_country": r.origin_country, "status": r.status,
                     "confidence_score": r.confidence_score}
                    for r in rows
                ]}
            finally:
                db.close()

        @mcp.tool()
        async def threats_save(
            name: str,
            classification: str | None = None,
            origin_country: str | None = None,
            motivation: str | None = None,
            sophistication: str | None = None,
            ttps: list[str] | None = None,
            aliases: list[str] | None = None,
            confidence_score: float = 0.5,
        ) -> dict:
            """Save a threat actor profile to BrainCell memory.

            Use when identifying a new threat actor, attributing an attack,
            or adding MITRE ATT&CK TTPs to a known group.
            classification: apt / criminal / hacktivist / state-sponsored / unknown
            sophistication: low / medium / high / nation-state
            motivation: espionage / financial / disruption / ideological
            ttps: list of MITRE ATT&CK technique IDs e.g. ['T1566', 'T1059.001']
            """
            db = SyncSessionLocal()
            try:
                actor = ThreatActor(
                    name=name,
                    classification=classification,
                    origin_country=origin_country,
                    motivation=motivation,
                    sophistication=sophistication,
                    ttps=ttps or [],
                    aliases=aliases or [],
                    confidence_score=confidence_score,
                    status="active",
                )
                db.add(actor)
                db.commit()
                db.refresh(actor)

                from itl_braincell_sdk.services.weaviate_service import get_weaviate_service
                get_weaviate_service().index(
                    "ThreatActor",
                    str(actor.id),
                    {
                        "name": actor.name,
                        "classification": actor.classification,
                        "motivation": actor.motivation,
                        "ttps": actor.ttps,
                    },
                )
                return {"status": "saved", "id": str(actor.id), "name": actor.name}
            finally:
                db.close()

        @mcp.tool()
        async def threats_semantic_search(query: str, limit: int = 10) -> dict:
            """Semantic (vector) search over threat actors by natural-language description.

            Use for fuzzy/conceptual queries the exact-match `threats_search` tool
            can't handle, e.g. 'financially motivated group targeting banks in Europe'.
            Falls back to an empty result set if Weaviate is unavailable.
            """
            from itl_braincell_sdk.services.weaviate_service import get_weaviate_service
            results = get_weaviate_service().near_text("ThreatActor", query, limit=limit)
            return {"query": query, "count": len(results), "results": results}

        @mcp.tool()
        async def threats_ttp_lookup(ttp_id: str) -> dict:
            """Find all threat actors known to use a specific MITRE ATT&CK technique.

            Use when responding to an alert that matches a known TTP
            and you need to narrow down attribution.
            Example: threats_ttp_lookup('T1566') → returns all actors using phishing.
            """
            db = SyncSessionLocal()
            try:
                from sqlalchemy import cast, String as _Str
                rows = db.query(ThreatActor).filter(
                    cast(ThreatActor.ttps, _Str).ilike(f"%{ttp_id}%")
                ).all()
                return {
                    "ttp_id": ttp_id,
                    "count": len(rows),
                    "actors": [
                        {"id": str(r.id), "name": r.name, "classification": r.classification,
                         "origin_country": r.origin_country, "sophistication": r.sophistication}
                        for r in rows
                    ],
                }
            finally:
                db.close()


cell = ThreatsCell()

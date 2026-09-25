"""Routes for threats cell"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from uuid import UUID

from itl_braincell_sdk.core.database import get_db
from itl_braincell_sdk.core.pagination import Pagination
from itl_braincell_sdk.services.weaviate_service import get_weaviate_service

from .model import ThreatActor
from .schema import ThreatActorCreate, ThreatActorResponse

router = APIRouter()


@router.get("", response_model=list[ThreatActorResponse])
async def list_threat_actors(pagination: Pagination = Depends(), db: Session = Depends(get_db)):
    """List threat actors (paginated, most recent first)."""
    return pagination.apply(
        db.query(ThreatActor).order_by(ThreatActor.created_at.desc())
    ).all()


@router.post("", response_model=ThreatActorResponse, status_code=201)
async def create_threat_actor(req: ThreatActorCreate, db: Session = Depends(get_db)):
    """Create a new threat actor profile."""
    actor = ThreatActor(**req.dict())
    db.add(actor)
    db.commit()
    db.refresh(actor)

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
    return actor


@router.get("/{actor_id}", response_model=ThreatActorResponse)
async def get_threat_actor(actor_id: UUID, db: Session = Depends(get_db)):
    """Get a specific threat actor by ID."""
    actor = db.query(ThreatActor).filter(ThreatActor.id == actor_id).first()
    if not actor:
        return {"error": "Threat actor not found"}, 404
    return actor


@router.get("/search/{query}", response_model=dict)
async def search_threat_actors(query: str, limit: int = 10, db: Session = Depends(get_db)):
    """Search threat actors by name, classification, or motivation."""
    q = query.lower()
    rows = db.query(ThreatActor).filter(
        ThreatActor.name.ilike(f"%{q}%") |
        ThreatActor.classification.ilike(f"%{q}%") |
        ThreatActor.motivation.ilike(f"%{q}%")
    ).limit(limit).all()
    return {
        "query": query,
        "count": len(rows),
        "results": [
            {
                "id": str(r.id),
                "name": r.name,
                "classification": r.classification,
                "motivation": r.motivation,
                "ttps": r.ttps,
                "origin_country": r.origin_country,
            }
            for r in rows
        ]
    }


@router.get("/semantic-search/{query}", response_model=dict)
async def semantic_search_threat_actors(query: str, limit: int = 10):
    """Semantic (vector) search over threat actors via Weaviate near-text query."""
    results = get_weaviate_service().near_text("ThreatActor", query, limit=limit)
    return {"query": query, "count": len(results), "results": results}

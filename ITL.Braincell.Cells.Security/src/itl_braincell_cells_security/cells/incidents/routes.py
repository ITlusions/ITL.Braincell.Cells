"""Routes for incidents cell"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from uuid import UUID

from itl_braincell_sdk.core.database import get_db
from itl_braincell_sdk.core.pagination import Pagination

from .model import SecurityIncident
from .schema import SecurityIncidentCreate, SecurityIncidentResponse

router = APIRouter()


@router.get("", response_model=list[SecurityIncidentResponse])
async def list_incidents(pagination: Pagination = Depends(), db: Session = Depends(get_db)):
    """List security incidents (paginated, most recent first)."""
    return pagination.apply(
        db.query(SecurityIncident).order_by(SecurityIncident.created_at.desc())
    ).all()


@router.post("", response_model=SecurityIncidentResponse, status_code=201)
async def create_incident(req: SecurityIncidentCreate, db: Session = Depends(get_db)):
    """Create a new security incident."""
    incident = SecurityIncident(**req.dict())
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


@router.get("/{incident_id}", response_model=SecurityIncidentResponse)
async def get_incident(incident_id: UUID, db: Session = Depends(get_db)):
    """Get a specific security incident by ID."""
    incident = db.query(SecurityIncident).filter(SecurityIncident.id == incident_id).first()
    if not incident:
        return {"error": "Incident not found"}, 404
    return incident


@router.get("/search/{query}", response_model=dict)
async def search_incidents(query: str, limit: int = 10, db: Session = Depends(get_db)):
    """Search incidents by title, description, or attack vector."""
    q = query.lower()
    rows = db.query(SecurityIncident).filter(
        SecurityIncident.title.ilike(f"%{q}%") |
        SecurityIncident.description.ilike(f"%{q}%") |
        SecurityIncident.attack_vector.ilike(f"%{q}%")
    ).limit(limit).all()
    return {
        "query": query,
        "count": len(rows),
        "results": [
            {
                "id": str(r.id),
                "title": r.title,
                "severity": r.severity,
                "status": r.status,
                "attack_vector": r.attack_vector,
                "threat_actor_name": r.threat_actor_name,
            }
            for r in rows
        ]
    }

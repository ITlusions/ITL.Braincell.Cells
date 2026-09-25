"""Routes for kill_chains cell"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from uuid import UUID

from itl_braincell_sdk.core.database import get_db
from itl_braincell_sdk.core.pagination import Pagination

from .model import KillChain
from .schema import KillChainCreate, KillChainResponse

router = APIRouter()


@router.get("", response_model=list[KillChainResponse])
async def list_kill_chains(pagination: Pagination = Depends(), db: Session = Depends(get_db)):
    """List attack kill chains (paginated, most recent first)."""
    return pagination.apply(
        db.query(KillChain).order_by(KillChain.created_at.desc())
    ).all()


@router.post("", response_model=KillChainResponse, status_code=201)
async def create_kill_chain(req: KillChainCreate, db: Session = Depends(get_db)):
    """Create a new attack kill chain."""
    chain = KillChain(**req.dict())
    db.add(chain)
    db.commit()
    db.refresh(chain)
    return chain


@router.get("/{chain_id}", response_model=KillChainResponse)
async def get_kill_chain(chain_id: UUID, db: Session = Depends(get_db)):
    """Get a specific kill chain by ID."""
    chain = db.query(KillChain).filter(KillChain.id == chain_id).first()
    if not chain:
        return {"error": "Kill chain not found"}, 404
    return chain


@router.get("/search/{query}", response_model=dict)
async def search_kill_chains(query: str, limit: int = 10, db: Session = Depends(get_db)):
    """Search kill chains by title, description, or threat actor."""
    q = query.lower()
    rows = db.query(KillChain).filter(
        KillChain.title.ilike(f"%{q}%") |
        KillChain.description.ilike(f"%{q}%") |
        KillChain.threat_actor_name.ilike(f"%{q}%")
    ).limit(limit).all()
    return {
        "query": query,
        "count": len(rows),
        "results": [
            {
                "id": str(r.id),
                "title": r.title,
                "threat_actor_name": r.threat_actor_name,
                "status": r.status,
                "stages": r.stages,
            }
            for r in rows
        ]
    }

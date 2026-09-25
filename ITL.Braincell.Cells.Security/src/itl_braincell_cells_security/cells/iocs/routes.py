"""Routes for iocs cell"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from uuid import UUID

from itl_braincell_sdk.core.database import get_db
from itl_braincell_sdk.core.pagination import Pagination

from .model import IOC
from .schema import IOCCreate, IOCResponse

router = APIRouter()


@router.get("", response_model=list[IOCResponse])
async def list_iocs(pagination: Pagination = Depends(), db: Session = Depends(get_db)):
    """List indicators of compromise (paginated, most recent first)."""
    return pagination.apply(
        db.query(IOC).order_by(IOC.created_at.desc())
    ).all()


@router.post("", response_model=IOCResponse, status_code=201)
async def create_ioc(req: IOCCreate, db: Session = Depends(get_db)):
    """Create a new IOC record."""
    ioc = IOC(**req.dict())
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return ioc


@router.get("/{ioc_id}", response_model=IOCResponse)
async def get_ioc(ioc_id: UUID, db: Session = Depends(get_db)):
    """Get a specific IOC by ID."""
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        return {"error": "IOC not found"}, 404
    return ioc


@router.get("/search/{query}", response_model=dict)
async def search_iocs(query: str, limit: int = 20, db: Session = Depends(get_db)):
    """Search IOCs by value, type, or context."""
    q = query.lower()
    rows = db.query(IOC).filter(
        IOC.value.ilike(f"%{q}%") |
        IOC.ioc_type.ilike(f"%{q}%") |
        IOC.context.ilike(f"%{q}%")
    ).limit(limit).all()
    return {
        "query": query,
        "count": len(rows),
        "results": [
            {
                "id": str(r.id),
                "ioc_type": r.ioc_type,
                "value": r.value,
                "severity": r.severity,
                "status": r.status,
                "source": r.source,
            }
            for r in rows
        ]
    }

"""Routes for vuln_patches cell"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from uuid import UUID

from itl_braincell_sdk.core.database import get_db
from itl_braincell_sdk.core.pagination import Pagination

from .model import VulnPatch
from .schema import VulnPatchCreate, VulnPatchResponse

router = APIRouter()


@router.get("", response_model=list[VulnPatchResponse])
async def list_vuln_patches(pagination: Pagination = Depends(), db: Session = Depends(get_db)):
    """List vulnerable/patched code pairs (paginated, most recent first)."""
    return pagination.apply(
        db.query(VulnPatch).order_by(VulnPatch.created_at.desc())
    ).all()


@router.post("", response_model=VulnPatchResponse, status_code=201)
async def create_vuln_patch(req: VulnPatchCreate, db: Session = Depends(get_db)):
    """Create a new vulnerable/patched code pair."""
    patch = VulnPatch(**req.dict())
    db.add(patch)
    db.commit()
    db.refresh(patch)
    return patch


@router.get("/{patch_id}", response_model=VulnPatchResponse)
async def get_vuln_patch(patch_id: UUID, db: Session = Depends(get_db)):
    """Get a specific vulnerable/patched code pair by ID."""
    patch = db.query(VulnPatch).filter(VulnPatch.id == patch_id).first()
    if not patch:
        return {"error": "Vuln patch not found"}, 404
    return patch


@router.get("/search/{query}", response_model=dict)
async def search_vuln_patches(query: str, limit: int = 10, db: Session = Depends(get_db)):
    """Search vulnerable/patched code pairs by title, description, or category."""
    q = query.lower()
    rows = db.query(VulnPatch).filter(
        VulnPatch.title.ilike(f"%{q}%") |
        VulnPatch.description.ilike(f"%{q}%") |
        VulnPatch.category.ilike(f"%{q}%")
    ).limit(limit).all()
    return {
        "query": query,
        "count": len(rows),
        "results": [
            {
                "id": str(r.id),
                "title": r.title,
                "category": r.category,
                "severity": r.severity,
                "language": r.language,
            }
            for r in rows
        ]
    }

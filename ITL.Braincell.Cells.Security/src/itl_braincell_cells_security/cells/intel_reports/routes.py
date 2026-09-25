"""Routes for intel_reports cell"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from uuid import UUID

from itl_braincell_sdk.core.database import get_db
from itl_braincell_sdk.core.pagination import Pagination

from .model import IntelReport
from .schema import IntelReportCreate, IntelReportResponse

router = APIRouter()


@router.get("", response_model=list[IntelReportResponse])
async def list_intel_reports(pagination: Pagination = Depends(), db: Session = Depends(get_db)):
    """List intelligence reports (paginated, most recent first)."""
    return pagination.apply(
        db.query(IntelReport).order_by(IntelReport.created_at.desc())
    ).all()


@router.post("", response_model=IntelReportResponse, status_code=201)
async def create_intel_report(req: IntelReportCreate, db: Session = Depends(get_db)):
    """Create a new intelligence report."""
    report = IntelReport(**req.dict())
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@router.get("/{report_id}", response_model=IntelReportResponse)
async def get_intel_report(report_id: UUID, db: Session = Depends(get_db)):
    """Get a specific intelligence report by ID."""
    report = db.query(IntelReport).filter(IntelReport.id == report_id).first()
    if not report:
        return {"error": "Intel report not found"}, 404
    return report


@router.get("/search/{query}", response_model=dict)
async def search_intel_reports(query: str, limit: int = 10, db: Session = Depends(get_db)):
    """Search intelligence reports by title or summary."""
    q = query.lower()
    rows = db.query(IntelReport).filter(
        IntelReport.title.ilike(f"%{q}%") |
        IntelReport.summary.ilike(f"%{q}%")
    ).limit(limit).all()
    return {
        "query": query,
        "count": len(rows),
        "results": [
            {
                "id": str(r.id),
                "title": r.title,
                "summary": r.summary,
                "tlp_level": r.tlp_level,
                "source": r.source,
            }
            for r in rows
        ]
    }

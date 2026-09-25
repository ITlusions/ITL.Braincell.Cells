"""Routes for vuln_reports cell"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from uuid import UUID

from itl_braincell_sdk.core.database import get_db
from itl_braincell_sdk.core.pagination import Pagination

from .model import VulnReport
from .schema import VulnReportCreate, VulnReportResponse

router = APIRouter()


@router.get("", response_model=list[VulnReportResponse])
async def list_vuln_reports(pagination: Pagination = Depends(), db: Session = Depends(get_db)):
    """List vulnerability reports (paginated, most recent first)."""
    return pagination.apply(
        db.query(VulnReport).order_by(VulnReport.created_at.desc())
    ).all()


@router.post("", response_model=VulnReportResponse, status_code=201)
async def create_vuln_report(req: VulnReportCreate, db: Session = Depends(get_db)):
    """Create a new vulnerability report."""
    report = VulnReport(**req.dict())
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@router.get("/{report_id}", response_model=VulnReportResponse)
async def get_vuln_report(report_id: UUID, db: Session = Depends(get_db)):
    """Get a specific vulnerability report by ID."""
    report = db.query(VulnReport).filter(VulnReport.id == report_id).first()
    if not report:
        return {"error": "Vulnerability report not found"}, 404
    return report


@router.get("/search/{query}", response_model=dict)
async def search_vuln_reports(query: str, limit: int = 10, db: Session = Depends(get_db)):
    """Search vulnerability reports by title, CVE ID, or affected component."""
    q = query.lower()
    rows = db.query(VulnReport).filter(
        VulnReport.title.ilike(f"%{q}%") |
        VulnReport.cve_id.ilike(f"%{q}%") |
        VulnReport.affected_component.ilike(f"%{q}%")
    ).limit(limit).all()
    return {
        "query": query,
        "count": len(rows),
        "results": [
            {
                "id": str(r.id),
                "title": r.title,
                "cve_id": r.cve_id,
                "cvss_score": r.cvss_score,
                "severity": r.severity,
                "status": r.status,
            }
            for r in rows
        ]
    }

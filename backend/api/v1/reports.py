from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from db.database import get_db
from core.permissions import get_current_user_optional
from schemas.common import ApiResponse
from services.report_service import ReportService

router = APIRouter(prefix="/reports", tags=["Security Audit Reports"])


@router.get("/{scan_id}", response_model=ApiResponse[Dict[str, Any]])
def get_scan_report(
    scan_id: str,
    current_user: Optional[dict] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Generate executive security summary and recommendations for a scan."""
    service = ReportService(db)
    is_admin = current_user.get("role") == "ADMIN" if current_user else False
    user_id = current_user.get("id") if current_user else None

    report = service.generate_report(scan_id=scan_id, user_id=user_id, is_admin=is_admin)
    return ApiResponse(
        success=True,
        message="Report generated successfully.",
        data=report,
    )

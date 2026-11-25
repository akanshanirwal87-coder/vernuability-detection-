from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from db.database import get_db
from core.permissions import get_current_user_optional, get_current_user
from schemas.common import ApiResponse
from schemas.finding import FindingUpdate
from services.finding_service import FindingService

router = APIRouter(prefix="/findings", tags=["Findings & Remediation Tracking"])


@router.put("/{finding_id}", response_model=ApiResponse[Dict[str, Any]])
def update_finding_status(
    finding_id: str,
    req: FindingUpdate,
    current_user: Optional[dict] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Update finding remediation status (e.g., OPEN, IN_REVIEW, RESOLVED, FALSE_POSITIVE)."""
    service = FindingService(db)
    is_admin = current_user.get("role") == "ADMIN" if current_user else False
    user_id = current_user.get("id") if current_user else None

    updated = service.update_finding(
        finding_id=finding_id,
        status=req.remediation_status,
        explanation=req.remediation_explanation,
        user_id=user_id,
        is_admin=is_admin,
    )

    return ApiResponse(
        success=True,
        message="Finding status updated successfully.",
        data=updated,
    )

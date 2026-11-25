from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, UploadFile, File, Form, Query, HTTPException, status
from sqlalchemy.orm import Session

from db.database import get_db
from core.permissions import get_current_user_optional, get_current_user, check_rate_limit
from core.security import validate_upload
from schemas.common import ApiResponse, PaginatedData, PaginationMeta
from schemas.scan import (
    ScanCreate,
    ScanRead,
    FixValidationRequest,
    FixValidationResponse,
    MultiFileScanRequest,
)
from services.scan_service import ScanService
from services.finding_service import FindingService
from services.remediation_service import RemediationService

router = APIRouter(prefix="/scans", tags=["Scan & Vulnerability Analysis"])


@router.post("", response_model=ApiResponse[Dict[str, Any]], status_code=status.HTTP_201_CREATED)
def create_scan(
    req: ScanCreate,
    current_user: Optional[dict] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
    _=Depends(check_rate_limit),
):
    """Initiate a static, AI/ML, and SCA vulnerability scan on submitted code."""
    service = ScanService(db)
    user_id = current_user.get("id") if current_user else None

    result = service.execute_scan(
        source_code=req.sourceCode,
        language=req.language,
        file_name=req.fileName or "source_code",
        project_name=req.projectName or "Direct Scan",
        project_id=req.projectId,
        user_id=user_id,
        enable_ai=req.options.enableAiClassifier if req.options else True,
        enable_rules=req.options.enableRuleMatching if req.options else True,
    )

    return ApiResponse(
        success=True,
        message="Scan completed successfully.",
        data=result,
    )


@router.post("/upload", response_model=ApiResponse[Dict[str, Any]], status_code=status.HTTP_201_CREATED)
async def upload_file_scan(
    projectName: str = Form("Uploaded Scan"),
    language: str = Form("python"),
    projectId: Optional[str] = Form(None),
    file: UploadFile = File(...),
    current_user: Optional[dict] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
    _=Depends(check_rate_limit),
):
    """Upload and statically scan a source file with strict path traversal & size validation."""
    content = await file.read()
    try:
        safe_name = validate_upload(file.filename or "", content)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    source_code = content.decode("utf-8")
    service = ScanService(db)
    user_id = current_user.get("id") if current_user else None

    result = service.execute_scan(
        source_code=source_code,
        language=language,
        file_name=safe_name,
        project_name=projectName,
        project_id=projectId,
        user_id=user_id,
    )

    return ApiResponse(
        success=True,
        message="File uploaded and analyzed successfully.",
        data=result,
    )


@router.get("", response_model=ApiResponse[PaginatedData[Dict[str, Any]]])
def list_scans(
    projectId: Optional[str] = Query(None),
    scanStatus: Optional[str] = Query(None, alias="status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    current_user: Optional[dict] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Retrieve historical scan audit records with optional project filtering and pagination."""
    service = ScanService(db)
    is_admin = current_user.get("role") == "ADMIN" if current_user else False
    user_id = None if is_admin else (current_user.get("id") if current_user else None)

    scans, total = service.list(
        user_id=user_id,
        project_id=projectId,
        status=scanStatus,
        skip=skip,
        limit=limit,
    )

    return ApiResponse(
        success=True,
        message="Scans retrieved successfully.",
        data=PaginatedData(
            items=scans,
            pagination=PaginationMeta(
                total=total,
                skip=skip,
                limit=limit,
                has_more=(skip + len(scans) < total),
            ),
        ),
    )


@router.get("/{scan_id}", response_model=ApiResponse[Dict[str, Any]])
def get_scan(
    scan_id: str,
    current_user: Optional[dict] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Retrieve complete scan report, findings count, AST summary, and AI metadata."""
    service = ScanService(db)
    is_admin = current_user.get("role") == "ADMIN" if current_user else False
    user_id = current_user.get("id") if current_user else None

    scan_data = service.get_by_id(scan_id=scan_id, user_id=user_id, is_admin=is_admin)
    return ApiResponse(
        success=True,
        message="Scan retrieved successfully.",
        data=scan_data,
    )


@router.get("/{scan_id}/findings", response_model=ApiResponse[PaginatedData[Dict[str, Any]]])
def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = Query(None),
    cwe: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: Optional[dict] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Retrieve detailed vulnerability findings for a specific scan with pagination & filters."""
    service = FindingService(db)
    is_admin = current_user.get("role") == "ADMIN" if current_user else False
    user_id = current_user.get("id") if current_user else None

    findings, total = service.list_findings(
        scan_id=scan_id,
        severity=severity,
        cwe=cwe,
        skip=skip,
        limit=limit,
        user_id=user_id,
        is_admin=is_admin,
    )

    return ApiResponse(
        success=True,
        message="Findings retrieved successfully.",
        data=PaginatedData(
            items=findings,
            pagination=PaginationMeta(
                total=total,
                skip=skip,
                limit=limit,
                has_more=(skip + len(findings) < total),
            ),
        ),
    )


@router.post("/{scan_id}/validate-fix", response_model=ApiResponse[FixValidationResponse])
def validate_fix(
    scan_id: str,
    req: FixValidationRequest,
    current_user: Optional[dict] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Recompile proposed remediation in AST sandbox to verify elimination of target sink."""
    service = RemediationService(db)
    is_admin = current_user.get("role") == "ADMIN" if current_user else False
    user_id = current_user.get("id") if current_user else None

    res = service.validate_code_fix(
        scan_id=scan_id,
        finding_id=req.findingId,
        proposed_code=req.proposedCode,
        user_id=user_id,
        is_admin=is_admin,
    )

    return ApiResponse(
        success=True,
        message="Remediation fix validated successfully.",
        data=FixValidationResponse(**res),
    )


@router.delete("/{scan_id}", response_model=ApiResponse[dict])
def delete_scan(
    scan_id: str,
    current_user: Optional[dict] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Delete a scan record and its associated findings."""
    service = ScanService(db)
    is_admin = current_user.get("role") == "ADMIN" if current_user else False
    user_id = current_user.get("id") if current_user else None

    service.delete(scan_id=scan_id, user_id=user_id, is_admin=is_admin)
    return ApiResponse(
        success=True,
        message="Scan deleted successfully.",
        data={"scanId": scan_id},
    )

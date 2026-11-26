import uuid
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from core.permissions import check_rate_limit, get_current_user
from schemas.common import ApiResponse
from analyzer.sca_scanner import sca_scanner
from analyzer.osv_client import osv_client

router = APIRouter(prefix="/dependencies", tags=["Software Composition Analysis (SCA)"])


class ScaManifestScanRequest(BaseModel):
    fileName: str
    content: str
    projectName: Optional[str] = "Dependency Manifest Scan"


class OsvQueryRequest(BaseModel):
    packageName: str
    ecosystem: Optional[str] = "PyPI"
    version: Optional[str] = None


@router.post("/scan", response_model=ApiResponse[Dict[str, Any]])
def scan_manifest(
    req: ScaManifestScanRequest,
    current_user: dict = Depends(get_current_user),
    _=Depends(check_rate_limit),
):
    """Perform Software Composition Analysis on package manifests against OSV.dev."""
    scan_id = f"sca-{uuid.uuid4().hex[:8]}"
    findings = sca_scanner.scan_manifest(req.fileName, req.content, scan_id)

    severities = [f.get("severity", "LOW") for f in findings]
    highest_sev = "CRITICAL" if "CRITICAL" in severities else ("HIGH" if "HIGH" in severities else ("MEDIUM" if "MEDIUM" in severities else "LOW"))
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": len(findings)}
    for f in findings:
        sev = f.get("severity", "LOW").lower()
        if sev in counts:
            counts[sev] += 1

    return ApiResponse(
        success=True,
        message="Dependency manifest scanned successfully.",
        data={
            "scanId": scan_id,
            "fileName": req.fileName,
            "dependenciesFound": len(findings),
            "highestSeverity": highest_sev,
            "findingsCount": counts,
            "findings": findings,
        },
    )


@router.post("/query", response_model=ApiResponse[Dict[str, Any]])
def query_package_osv(
    req: OsvQueryRequest,
    current_user: dict = Depends(get_current_user),
    _=Depends(check_rate_limit),
):
    """Direct package vulnerability lookup in the Google OSV.dev database."""
    results = osv_client.query_package(req.packageName, req.ecosystem or "PyPI", req.version)
    return ApiResponse(
        success=True,
        message="OSV.dev package queried successfully.",
        data={
            "package": req.packageName,
            "ecosystem": req.ecosystem,
            "version": req.version,
            "vulnerabilitiesFound": len(results),
            "results": results,
            "source": "https://osv.dev/",
        },
    )

import pytest


def test_list_and_update_finding(client, auth_headers):
    """Test retrieving findings for a scan and updating remediation status."""
    vulnerable_code = "cursor.execute('SELECT * FROM t WHERE id = ' + user_id)"
    scan_res = client.post(
        "/api/v1/scans",
        json={"sourceCode": vulnerable_code, "language": "python", "fileName": "query.py"},
        headers=auth_headers,
    )
    scan_id = scan_res.json()["data"]["id"]
    findings = scan_res.json()["data"]["findings"]
    assert len(findings) >= 1
    finding_id = findings[0]["id"]

    # Retrieve findings via GET
    list_res = client.get(f"/api/v1/scans/{scan_id}/findings", headers=auth_headers)
    assert list_res.status_code == 200
    assert len(list_res.json()["data"]["items"]) >= 1

    # Update finding remediation status
    update_res = client.put(
        f"/api/v1/findings/{finding_id}",
        json={
            "remediation_status": "RESOLVED",
            "remediation_explanation": "Replaced raw string concatenation with parameterized query.",
        },
        headers=auth_headers,
    )
    assert update_res.status_code == 200
    assert update_res.json()["data"]["remediationStatus"] == "RESOLVED"


def test_validate_code_fix(client, auth_headers):
    """Test AST fix verification engine validating remediation code."""
    vulnerable_code = "cursor.execute('SELECT * FROM t WHERE id = ' + user_id)"
    scan_res = client.post(
        "/api/v1/scans",
        json={"sourceCode": vulnerable_code, "language": "python", "fileName": "query.py"},
        headers=auth_headers,
    )
    scan_id = scan_res.json()["data"]["id"]
    finding_id = scan_res.json()["data"]["findings"][0]["id"]

    # Submit valid parameterized fix
    secure_fix = "cursor.execute('SELECT * FROM t WHERE id = ?', (user_id,))"
    fix_res = client.post(
        f"/api/v1/scans/{scan_id}/validate-fix",
        json={"findingId": finding_id, "proposedCode": secure_fix},
        headers=auth_headers,
    )
    assert fix_res.status_code == 200
    body = fix_res.json()
    assert body["success"] is True
    assert body["data"]["passed"] is True
    assert body["data"]["status"] == "VALIDATION_PASSED"

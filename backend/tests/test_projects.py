import pytest


def test_create_project(client, auth_headers):
    """Test creating a project owned by the authenticated user."""
    res = client.post(
        "/api/v1/projects",
        json={
            "name": "Cloud Security Agent",
            "description": "Microservice for automated scanning",
            "repository_url": "https://github.com/securecode/agent",
        },
        headers=auth_headers,
    )
    assert res.status_code == 201
    body = res.json()
    assert body["success"] is True
    assert body["data"]["name"] == "Cloud Security Agent"
    assert "id" in body["data"]


def test_create_duplicate_project_name(client, auth_headers, sample_project):
    """Test creating project with duplicate name for same user returns 409 Conflict."""
    res = client.post(
        "/api/v1/projects",
        json={"name": sample_project.name},
        headers=auth_headers,
    )
    assert res.status_code == 409
    assert res.json()["error_code"] == "RESOURCE_CONFLICT"


def test_list_projects_pagination_and_search(client, auth_headers, sample_project):
    """Test listing user projects with search and pagination."""
    res = client.get(
        "/api/v1/projects",
        params={"skip": 0, "limit": 10, "search": "E-Commerce"},
        headers=auth_headers,
    )
    assert res.status_code == 200
    body = res.json()
    assert body["success"] is True
    assert len(body["data"]["items"]) >= 1
    assert body["data"]["pagination"]["total"] >= 1


def test_cross_user_project_access_denied(client, second_user_headers, sample_project):
    """Verify user B cannot access or modify user A's project (cross-user isolation)."""
    # User B attempts to access User A's project
    res = client.get(
        f"/api/v1/projects/{sample_project.id}",
        headers=second_user_headers,
    )
    assert res.status_code == 403
    assert res.json()["error_code"] == "FORBIDDEN"

    # User B attempts to delete User A's project
    del_res = client.delete(
        f"/api/v1/projects/{sample_project.id}",
        headers=second_user_headers,
    )
    assert del_res.status_code == 403


def test_admin_can_access_any_project(client, admin_headers, sample_project):
    """Verify administrator role can view other users' projects."""
    res = client.get(
        f"/api/v1/projects/{sample_project.id}",
        headers=admin_headers,
    )
    assert res.status_code == 200
    assert res.json()["data"]["id"] == sample_project.id


def test_update_and_delete_project(client, auth_headers, sample_project):
    """Test updating and deleting own project."""
    up_res = client.put(
        f"/api/v1/projects/{sample_project.id}",
        json={"name": "Renamed Core", "description": "Updated description"},
        headers=auth_headers,
    )
    assert up_res.status_code == 200
    assert up_res.json()["data"]["name"] == "Renamed Core"

    del_res = client.delete(
        f"/api/v1/projects/{sample_project.id}",
        headers=auth_headers,
    )
    assert del_res.status_code == 200

    # Ensure deleted
    get_res = client.get(
        f"/api/v1/projects/{sample_project.id}",
        headers=auth_headers,
    )
    assert get_res.status_code == 404

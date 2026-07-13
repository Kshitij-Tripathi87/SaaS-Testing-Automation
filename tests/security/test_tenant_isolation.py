"""
Security Tests: Tenant Isolation

These tests verify that data belonging to one tenant cannot be
accessed by another tenant. This is a critical security boundary
for any B2B SaaS platform.
"""

import os
import pytest
from src.api.client import APIClient
from data.factories.project_factory import ProjectFactory


@pytest.fixture(scope="function")
def company1_client(env_config):
    return APIClient(
        base_url=env_config.api_url,
        tenant_id="company1",
        auth_token=os.getenv("COMPANY1_TOKEN", "mock-token"),
    )


@pytest.fixture(scope="function")
def company2_client(env_config):
    return APIClient(
        base_url=env_config.api_url,
        tenant_id="company2",
        auth_token=os.getenv("COMPANY2_TOKEN", "mock-token"),
    )


@pytest.mark.security
class TestTenantIsolation:

    def test_company_cannot_access_other_company_project(
        self, company1_client, company2_client
    ):
        """Company1 creates a project; Company2 must not be able to read it."""
        data = ProjectFactory.generate(tenant_id="company1")
        project = company1_client.post("/api/v1/projects", json=data)
        project.raise_for_status()
        project_id = project.json()["id"]

        try:
            response = company2_client.get(f"/api/v1/projects/{project_id}")
            assert response.status_code in (403, 404), (
                f"Security breach: Company2 accessed Company1's "
                f"project {project_id}. Status: {response.status_code}"
            )
        finally:
            company1_client.delete(f"/api/v1/projects/{project_id}")

    def test_company_cannot_list_other_company_projects(
        self, company1_client, company2_client
    ):
        """Company1 creates a project; Company2's list must not include it."""
        data = ProjectFactory.generate(tenant_id="company1")
        project = company1_client.post("/api/v1/projects", json=data)
        project.raise_for_status()
        project_id = project.json()["id"]

        try:
            response = company2_client.get("/api/v1/projects")
            response.raise_for_status()
            projects = response.json().get("projects", [])
            ids = [p["id"] for p in projects]
            assert project_id not in ids, (
                f"Security breach: Company2's project list contains "
                f"Company1's project {project_id}"
            )
        finally:
            company1_client.delete(f"/api/v1/projects/{project_id}")

    def test_company_cannot_modify_other_company_project(
        self, company1_client, company2_client
    ):
        """Company2 must not be able to update Company1's project."""
        data = ProjectFactory.generate(tenant_id="company1")
        project = company1_client.post("/api/v1/projects", json=data)
        project.raise_for_status()
        project_id = project.json()["id"]

        try:
            response = company2_client.put(
                f"/api/v1/projects/{project_id}",
                json={"name": "Hacked Project Name"},
            )
            assert response.status_code in (403, 404), (
                f"Security breach: Company2 modified Company1's "
                f"project {project_id}. Status: {response.status_code}"
            )
        finally:
            company1_client.delete(f"/api/v1/projects/{project_id}")

    def test_company_cannot_delete_other_company_project(
        self, company1_client, company2_client
    ):
        """Company2 must not be able to delete Company1's project."""
        data = ProjectFactory.generate(tenant_id="company1")
        project = company1_client.post("/api/v1/projects", json=data)
        project.raise_for_status()
        project_id = project.json()["id"]

        try:
            response = company2_client.delete(
                f"/api/v1/projects/{project_id}"
            )
            assert response.status_code in (403, 404), (
                f"Security breach: Company2 deleted Company1's "
                f"project {project_id}. Status: {response.status_code}"
            )

            still_exists = company1_client.get(
                f"/api/v1/projects/{project_id}"
            )
            assert still_exists.status_code == 200, (
                "Project was deleted despite 403 response"
            )
        finally:
            company1_client.delete(f"/api/v1/projects/{project_id}")

    def test_same_company_can_access_own_project(
        self, company1_client
    ):
        """Positive control: Same tenant must be able to access own data."""
        data = ProjectFactory.generate(tenant_id="company1")
        project = company1_client.post("/api/v1/projects", json=data)
        project.raise_for_status()
        project_id = project.json()["id"]

        try:
            response = company1_client.get(f"/api/v1/projects/{project_id}")
            assert response.status_code == 200, (
                f"Company1 could not access own project {project_id}. "
                f"Status: {response.status_code}"
            )
        finally:
            company1_client.delete(f"/api/v1/projects/{project_id}")

"""Tests for run submission, status, and completion."""


def test_create_and_get_key(client):
    """Bootstrap: create an API key."""
    resp = client.post("/v1/keys", json={
        "project_id": "default",
        "label": "test-key",
        "scopes": ["run_tests", "read_reports", "admin"],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "raw_key" in data
    assert data["raw_key"].startswith("ts_live_")


def test_submit_run_without_auth_fails(client):
    resp = client.post("/v1/runs", json={"goal": "security"})
    assert resp.status_code == 401


def test_full_run_lifecycle(client):
    """End-to-end: create key -> submit run -> poll -> stream logs -> complete -> verify."""
    # 1. Create API key
    key_resp = client.post("/v1/keys", json={
        "project_id": "default",
        "label": "lifecycle",
        "scopes": ["run_tests", "read_reports", "admin"],
    })
    assert key_resp.status_code == 200, key_resp.text
    raw_key = key_resp.json()["raw_key"]
    headers = {"X-TenantShield-Key": raw_key}

    # 2. Submit a run
    spec = {"goal": "security", "markers": ["security"], "env": {"TEST_ENV": "staging"}}
    resp = client.post("/v1/runs", json=spec, headers=headers)
    assert resp.status_code == 202, resp.text
    run_id = resp.json()["run_id"]
    assert run_id

    # 3. Poll status (should be queued)
    resp = client.get(f"/v1/runs/{run_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "queued"
    assert resp.json()["goal"] == "security"

    # 4. Stream logs (simulating worker)
    resp = client.post(f"/v1/runs/{run_id}/logs", params={"log_line": "Starting tests..."}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["ack"] is True

    # 5. Check status changed to running
    resp = client.get(f"/v1/runs/{run_id}", headers=headers)
    assert resp.json()["status"] == "running"

    # 6. Complete the run (simulating worker)
    resp = client.post(
        f"/v1/runs/{run_id}/complete",
        json={
            "total": 5,
            "passed": 5,
            "failed": 0,
            "skipped": 0,
            "duration_seconds": 12.5,
        },
        headers=headers,
    )
    assert resp.status_code == 200

    # 7. Verify final summary
    resp = client.get(f"/v1/runs/{run_id}", headers=headers)
    data = resp.json()
    assert data["status"] == "completed"
    assert data["summary"]["total"] == 5
    assert data["summary"]["passed"] == 5
    assert data["summary"]["duration_seconds"] == 12.5


def test_list_runs(client):
    key_resp = client.post("/v1/keys", json={"scopes": ["run_tests", "read_reports", "admin"]})
    raw_key = key_resp.json()["raw_key"]
    headers = {"X-TenantShield-Key": raw_key}

    # Submit two runs
    client.post("/v1/runs", json={"goal": "smoke"}, headers=headers)
    client.post("/v1/runs", json={"goal": "security"}, headers=headers)

    resp = client.get("/v1/runs", headers=headers)
    assert resp.status_code == 200
    runs = resp.json()
    assert len(runs) >= 2


def test_cancel_run(client):
    key_resp = client.post("/v1/keys", json={"scopes": ["run_tests", "read_reports", "admin"]})
    raw_key = key_resp.json()["raw_key"]
    headers = {"X-TenantShield-Key": raw_key}

    resp = client.post("/v1/runs", json={"goal": "regression"}, headers=headers)
    run_id = resp.json()["run_id"]

    resp = client.post(f"/v1/runs/{run_id}/cancel", headers=headers)
    assert resp.status_code == 200

    resp = client.get(f"/v1/runs/{run_id}", headers=headers)
    assert resp.json()["status"] == "cancelled"


def test_get_nonexistent_run(client):
    resp = client.get("/v1/runs/nonexistent-id")
    assert resp.status_code == 404


def test_run_results_and_artifacts(client):
    """Test results listing and artifact endpoints."""
    key_resp = client.post("/v1/keys", json={"scopes": ["run_tests", "read_reports", "admin"]})
    raw_key = key_resp.json()["raw_key"]
    headers = {"X-TenantShield-Key": raw_key}

    # Submit + complete a run
    run_id = client.post("/v1/runs", json={"goal": "security"}, headers=headers).json()["run_id"]
    client.post(f"/v1/runs/{run_id}/complete", json={"passed": 3, "total": 3}, headers=headers)

    # Get results
    resp = client.get(f"/v1/runs/{run_id}/results")
    assert resp.status_code == 200

    # Get artifacts list
    resp = client.get(f"/v1/runs/{run_id}/artifacts")
    assert resp.status_code == 200

    # Get report link
    resp = client.get(f"/v1/runs/{run_id}/report")
    assert resp.status_code == 200
    assert "report_url" in resp.json()

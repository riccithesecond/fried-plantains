"""
Tests for JWT authentication endpoints.

Security tests:
  - Expired tokens → 401, not 500
  - Tampered tokens → 401
  - Missing Authorization header → 401
  - Wrong password → 401
"""

import pytest
from fastapi.testclient import TestClient

# Must set env vars before importing app
import os
os.environ["SECRET_KEY"] = "test-secret-key-that-is-at-least-32-characters"
os.environ["ADMIN_USERNAME"] = "testadmin"
# bcrypt hash for "testpassword"
os.environ["ADMIN_PASSWORD_HASH"] = "$2b$12$KIXqaO/IWmjc.H55p5YIKuIgHy9X6ZIiqmJN4q5IB8.a.RuBRqhYS"
os.environ["CORS_ORIGIN"] = "http://localhost:5173"
os.environ["STORAGE_ROOT"] = "./test_storage"


@pytest.fixture(scope="module")
def client():
    from backend.main import app
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


class TestLogin:
    def test_missing_credentials_returns_422(self, client):
        resp = client.post("/api/v1/auth/token", data={})
        assert resp.status_code in (401, 422)

    def test_wrong_password_returns_401(self, client):
        resp = client.post(
            "/api/v1/auth/token",
            data={"username": "testadmin", "password": "wrongpassword"},
        )
        assert resp.status_code == 401

    def test_wrong_username_returns_401(self, client):
        resp = client.post(
            "/api/v1/auth/token",
            data={"username": "notauser", "password": "testpassword"},
        )
        assert resp.status_code == 401


class TestProtectedEndpoints:
    def test_query_without_token_returns_401(self, client):
        resp = client.post(
            "/api/v1/query/execute",
            json={"query": "DeviceProcessEvents | limit 10", "language": "kql"},
        )
        assert resp.status_code == 401

    def test_ingest_without_token_returns_401(self, client):
        resp = client.post("/api/v1/ingest/upload")
        assert resp.status_code == 401

    def test_detections_without_token_returns_401(self, client):
        resp = client.get("/api/v1/detections/")
        assert resp.status_code == 401

    def test_tampered_token_returns_401(self, client):
        resp = client.get(
            "/api/v1/detections/",
            headers={"Authorization": "Bearer tampered.token.here"},
        )
        assert resp.status_code == 401

    def test_expired_token_returns_401_not_500(self, client):
        from jose import jwt
        import datetime
        expired_token = jwt.encode(
            {
                "sub": "testadmin",
                "type": "access",
                "exp": datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc),
                "iat": datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc),
            },
            "test-secret-key-that-is-at-least-32-characters",
            algorithm="HS256",
        )
        resp = client.get(
            "/api/v1/detections/",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert resp.status_code == 401
        # Must not be a 500 — expired token is auth failure, not server error
        assert resp.status_code != 500


class TestHealthEndpoint:
    def test_health_is_public(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestSecurityHeaders:
    """Verify security headers are present on every response.

    Uses the public /health endpoint so no auth token is needed. Headers
    are injected by middleware and must appear regardless of route.
    """

    def _get(self, client):
        return client.get("/api/v1/health")

    def test_csp_report_only_present(self, client):
        resp = self._get(client)
        assert "content-security-policy-report-only" in resp.headers

    def test_csp_contains_default_src_self(self, client):
        resp = self._get(client)
        csp = resp.headers["content-security-policy-report-only"]
        assert "default-src 'self'" in csp

    def test_x_content_type_options_nosniff(self, client):
        resp = self._get(client)
        assert resp.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options_deny(self, client):
        resp = self._get(client)
        assert resp.headers.get("x-frame-options") == "DENY"

    def test_referrer_policy_set(self, client):
        resp = self._get(client)
        assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    def test_permissions_policy_set(self, client):
        resp = self._get(client)
        assert "permissions-policy" in resp.headers

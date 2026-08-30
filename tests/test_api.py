"""The user-facing contract: sign in, and the gateway does the rest."""

from __future__ import annotations

import asyncio
import io
import tarfile

import pytest
from fastapi.testclient import TestClient

from turbobond.app.api import create_app
from turbobond.config import AppConfig

PASSWORD = "correct-horse-battery"


@pytest.fixture
def client(cfg: AppConfig):
    cfg.auto_activate_on_login = False  # activation is exercised separately
    with TestClient(create_app(cfg)) as test_client:
        yield test_client


@pytest.fixture
def signed_in(client: TestClient) -> TestClient:
    response = client.post("/api/signin", json={"username": "admin", "password": PASSWORD})
    assert response.status_code == 200
    client.headers["X-TurboBond-CSRF"] = response.json()["csrf"]
    return client


class TestBootstrap:
    def test_bootstrap_is_public(self, client: TestClient) -> None:
        body = client.get("/api/bootstrap").json()
        assert body["enrolled"] is False
        assert body["profile"] == "wrt-turbo-search"

    def test_bootstrap_lists_both_routes(self, client: TestClient) -> None:
        names = {route["name"] for route in client.get("/api/bootstrap").json()["routes"]}
        assert names == {"direct", "shadow"}

    def test_health_is_public(self, client: TestClient) -> None:
        assert client.get("/api/health").json()["status"] == "ok"

    def test_the_control_panel_is_served(self, client: TestClient) -> None:
        response = client.get("/")
        assert response.status_code == 200
        assert "turbobond" in response.text
        assert "Sign in" in response.text


class TestSignIn:
    def test_first_sign_in_claims_the_account(self, client: TestClient) -> None:
        """No default password is ever shipped."""

        assert client.get("/api/bootstrap").json()["enrolled"] is False
        assert client.post("/api/signin", json={"password": PASSWORD}).status_code == 200
        assert client.get("/api/bootstrap").json()["enrolled"] is True

    def test_the_claimed_password_is_then_required(self, client: TestClient) -> None:
        client.post("/api/signin", json={"password": PASSWORD})
        client.post("/api/signout")
        assert client.post("/api/signin", json={"password": "wrong-password"}).status_code == 401
        assert client.post("/api/signin", json={"password": PASSWORD}).status_code == 200

    def test_a_short_password_is_refused(self, client: TestClient) -> None:
        response = client.post("/api/signin", json={"password": "short"})
        assert response.status_code == 401
        assert "8 characters" in response.json()["detail"]["message"]

    def test_sign_in_sets_an_httponly_cookie(self, client: TestClient) -> None:
        response = client.post("/api/signin", json={"password": PASSWORD})
        header = response.headers.get("set-cookie", "")
        assert "turbobond_session" in header
        assert "HttpOnly" in header
        assert "SameSite=strict" in header.replace("samesite", "SameSite")

    def test_repeated_failures_lock_the_account(self, client: TestClient) -> None:
        client.post("/api/signin", json={"password": PASSWORD})
        client.post("/api/signout")
        for _ in range(9):
            client.post("/api/signin", json={"password": "wrong-password"})
        response = client.post("/api/signin", json={"password": PASSWORD})
        assert response.status_code == 401
        assert "too many failed" in response.json()["detail"]["message"]

    def test_sign_out_invalidates_the_session(self, signed_in: TestClient) -> None:
        assert signed_in.get("/api/status").status_code == 200
        signed_in.post("/api/signout")
        assert signed_in.get("/api/status").status_code == 401


class TestFirstRunSettings:
    def test_credentials_supplied_at_sign_in_are_stored(self, client: TestClient, cfg: AppConfig) -> None:
        """Setup is one screen; the user never edits a config file."""

        client.post(
            "/api/signin",
            json={
                "password": PASSWORD,
                "router_host": "192.168.1.254",
                "router_password": "router-secret",
                "concentrator_host": "vps.example.com",
                "concentrator_port": 5400,
                "shadowsocks_host": "ss.example.com",
                "shadowsocks_password": "ss-secret",
            },
        )
        assert cfg.router.host == "192.168.1.254"
        assert cfg.router.password == "router-secret"
        assert cfg.concentrator.enabled and cfg.concentrator.host == "vps.example.com"
        assert cfg.concentrator.port == 5400
        assert cfg.shadowsocks.usable

    def test_omitted_settings_are_left_alone(self, client: TestClient, cfg: AppConfig) -> None:
        client.post("/api/signin", json={"password": PASSWORD})
        assert cfg.concentrator.host == ""
        assert not cfg.concentrator.enabled


class TestAuthorization:
    @pytest.mark.parametrize(
        "path",
        ["/api/status", "/api/links", "/api/routes", "/api/devices", "/api/sip", "/api/config", "/api/logs"],
    )
    def test_endpoints_require_a_session(self, client: TestClient, path: str) -> None:
        assert client.get(path).status_code == 401

    @pytest.mark.parametrize("path", ["/api/activate", "/api/deactivate"])
    def test_mutations_require_a_session(self, client: TestClient, path: str) -> None:
        assert client.post(path).status_code == 401

    def test_mutations_require_a_csrf_token(self, client: TestClient) -> None:
        client.post("/api/signin", json={"password": PASSWORD})
        # Cookie is set, but the CSRF header is not.
        assert client.post("/api/activate").status_code == 403

    def test_a_forged_csrf_token_is_rejected(self, signed_in: TestClient) -> None:
        signed_in.headers["X-TurboBond-CSRF"] = "forged"
        assert signed_in.post("/api/activate").status_code == 403


class TestStatusEndpoints:
    def test_status_reports_the_idle_phase_before_activation(self, signed_in: TestClient) -> None:
        body = signed_in.get("/api/status").json()
        assert body["phase"] == "idle"
        assert body["version"]

    def test_config_is_returned_with_secrets_masked(self, signed_in: TestClient, cfg: AppConfig) -> None:
        cfg.router.password = "router-secret"
        body = signed_in.get("/api/config").json()
        assert body["router"]["password"] == "********"
        assert "router-secret" not in str(body)

    def test_sip_endpoint_exposes_the_generated_ruleset(self, signed_in: TestClient) -> None:
        body = signed_in.get("/api/sip").json()
        assert "table inet turbobond" in body["ruleset"]
        assert body["config"]["wide_open"] is True

    def test_routes_endpoint_describes_both_options(self, signed_in: TestClient) -> None:
        body = signed_in.get("/api/routes").json()
        names = {route["name"] for route in body["available"]}
        assert names == {"direct", "shadow"}
        shadow = next(r for r in body["available"] if r["name"] == "shadow")
        assert shadow["obfuscated"] is True
        # Proxying RTP adds jitter, so voice stays on the direct route.
        assert shadow["carries_sip"] is False

    def test_command_audit_is_exposed(self, signed_in: TestClient) -> None:
        assert "commands" in signed_in.get("/api/commands").json()

    def test_logs_are_exposed(self, signed_in: TestClient) -> None:
        assert isinstance(signed_in.get("/api/logs").json()["records"], list)


class TestConfigPatch:
    def test_a_nested_patch_is_merged_and_persisted(self, signed_in: TestClient, cfg: AppConfig) -> None:
        response = signed_in.patch(
            "/api/config",
            json={"values": {"sip": {"rtp_port_start": 16384, "rtp_port_end": 32767}}},
        )
        assert response.status_code == 200
        assert cfg.sip.rtp_port_start == 16384
        assert cfg.sip.rtp_port_end == 32767
        # Unrelated fields survive the merge.
        assert cfg.sip.wide_open is True

    def test_an_invalid_patch_is_rejected(self, signed_in: TestClient, cfg: AppConfig) -> None:
        response = signed_in.patch(
            "/api/config",
            json={"values": {"sip": {"rtp_port_start": 40000, "rtp_port_end": 100}}},
        )
        assert response.status_code == 400
        assert cfg.sip.rtp_port_start == 10000


class TestDownloads:
    def test_the_concentrator_bundle_is_a_usable_tarball(self, signed_in: TestClient) -> None:
        response = signed_in.get("/api/download/concentrator")
        assert response.status_code == 200

        with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
            names = sorted(member.name for member in tar.getmembers())
            assert names == [
                "turbobond-concentrator/README.md",
                "turbobond-concentrator/install.sh",
                "turbobond-concentrator/turbobond-concentrator.service",
            ]
            service = tar.extractfile("turbobond-concentrator/turbobond-concentrator.service")
            assert service is not None
            body = service.read().decode()

        # Pre-paired so the two halves never have to be matched up by hand.
        assert "TURBOBOND_PSK=" in body
        assert "turbobond-server" in body

    def test_the_bundle_generates_a_key_when_none_exists(self, signed_in: TestClient, cfg: AppConfig) -> None:
        assert cfg.concentrator.psk_hex == ""
        signed_in.get("/api/download/concentrator")
        assert len(cfg.concentrator.psk_hex) == 64

    def test_config_download_is_redacted(self, signed_in: TestClient, cfg: AppConfig) -> None:
        cfg.router.password = "router-secret"
        body = signed_in.get("/api/download/config").text
        assert "router-secret" not in body
        assert "********" in body

    def test_diagnostics_bundle_includes_the_ruleset(self, signed_in: TestClient) -> None:
        body = signed_in.get("/api/download/diagnostics").json()
        assert "table inet turbobond" in body["sip_ruleset"]
        assert "status" in body
        assert "commands" in body

    def test_downloads_require_a_session(self, client: TestClient) -> None:
        assert client.get("/api/download/concentrator").status_code == 401
        assert client.get("/api/download/diagnostics").status_code == 401


class TestActivationThroughTheApi:
    def test_signing_in_activates_when_configured_to(self, cfg: AppConfig) -> None:
        """The whole point: the user signs in and nothing else."""

        cfg.auto_activate_on_login = True
        with TestClient(create_app(cfg)) as client:
            body = client.post("/api/signin", json={"password": PASSWORD}).json()
            assert body["activation"] is not None
            assert body["activation"]["running"] is True

            for _ in range(100):
                state = client.get("/api/activation").json()
                if not state["running"]:
                    break
                asyncio.run(asyncio.sleep(0.05))

            status = client.get("/api/status").json()
            assert status["phase"] in ("active", "degraded"), status.get("last_error")
            assert status["aggregate"]["uplinks"] >= 2

    def test_activation_can_be_triggered_manually(self, signed_in: TestClient) -> None:
        assert signed_in.post("/api/activate").json()["running"] is True

    def test_route_selection_needs_an_active_bond(self, signed_in: TestClient) -> None:
        response = signed_in.post("/api/routes/select", json={"route": "shadow"})
        assert response.status_code == 409

    def test_an_unknown_route_is_rejected(self, signed_in: TestClient) -> None:
        assert signed_in.post("/api/routes/select", json={"route": "nonsense"}).status_code == 422


class TestPasswordChange:
    def test_password_can_be_changed(self, signed_in: TestClient) -> None:
        response = signed_in.post(
            "/api/password",
            json={"current_password": PASSWORD, "new_password": "a-new-long-password"},
        )
        assert response.status_code == 200
        signed_in.post("/api/signout")
        assert signed_in.post("/api/signin", json={"password": "a-new-long-password"}).status_code == 200

    def test_the_current_password_must_be_correct(self, signed_in: TestClient) -> None:
        response = signed_in.post(
            "/api/password",
            json={"current_password": "wrong-password", "new_password": "a-new-long-password"},
        )
        assert response.status_code == 400

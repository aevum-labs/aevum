"""Smoke tests for /_aevum/v1/* admin API endpoints."""

from fastapi.testclient import TestClient


def test_list_complications_returns_empty_dict(authed_client: TestClient) -> None:
    r = authed_client.get("/_aevum/v1/complications")
    assert r.status_code == 200
    assert r.json() == {"complications": {}}


def test_approve_unknown_complication_returns_409(authed_client: TestClient) -> None:
    r = authed_client.post("/_aevum/v1/complications/no-such-comp/approve", json={})
    assert r.status_code == 409


def test_suspend_unknown_complication_returns_409(authed_client: TestClient) -> None:
    r = authed_client.post("/_aevum/v1/complications/no-such-comp/suspend", json={})
    assert r.status_code == 409


def test_complication_health_unknown_returns_404(authed_client: TestClient) -> None:
    r = authed_client.get("/_aevum/v1/complications/no-such-comp/health")
    assert r.status_code == 404


def test_usage_returns_200(authed_client: TestClient) -> None:
    r = authed_client.get("/_aevum/v1/usage")
    assert r.status_code == 200
    assert "usage" in r.json()


def test_federation_peers_returns_empty_list(authed_client: TestClient) -> None:
    r = authed_client.get("/_aevum/v1/federation/peers")
    assert r.status_code == 200
    assert r.json()["peers"] == []

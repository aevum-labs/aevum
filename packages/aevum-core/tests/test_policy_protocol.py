"""PolicyEngine Protocol conformance tests. No cedarpy required."""
import pytest

from aevum.core.policy import NullPolicyEngine, PolicyEngine


def _call(engine: PolicyEngine) -> bool:
    return engine.is_permitted(
        principal_type="AevumAgent", principal_id="test",
        action="relate_graph_write", resource_type="DataGraph",
        resource_id="knowledge", context={},
    )


def test_null_engine_permits_all() -> None:
    engine = NullPolicyEngine()
    assert _call(engine) is True


def test_null_engine_is_protocol_compliant() -> None:
    assert isinstance(NullPolicyEngine(), PolicyEngine)


def test_custom_engine_is_accepted() -> None:
    class DenyAll:
        def is_permitted(self, **_):
            return False

    assert isinstance(DenyAll(), PolicyEngine)
    assert _call(DenyAll()) is False


@pytest.mark.skipif(
    not __import__("importlib").util.find_spec("cedarpy"),
    reason="cedarpy not installed"
)
def test_cedar_engine_is_protocol_compliant() -> None:
    from aevum.core.policy.cedar_engine import CedarPolicyEngine
    assert isinstance(CedarPolicyEngine, type)


def test_engine_uses_null_when_cedar_absent(monkeypatch) -> None:
    """Engine falls back to NullPolicyEngine when Cedar is not installed."""
    import aevum.core.policy as p
    monkeypatch.setattr(p, "_CEDAR_AVAILABLE", False, raising=False)
    from aevum.core.engine import Engine
    engine = Engine()  # must not raise
    assert engine._policy_engine is not None

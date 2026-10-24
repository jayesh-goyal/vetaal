import pytest
from vetaal.security.scope_validator import ScopeValidator, ScopeViolationError

def test_scope_validator_allowed():
    validator = ScopeValidator({"scope": {"allowed_networks": ["127.0.0.0/8"], "allowed_commands": ["curl"]}})
    assert validator.validate_command(["curl", "http://127.0.0.1"]) is True

def test_scope_validator_denied():
    validator = ScopeValidator({"scope": {"allowed_networks": ["127.0.0.0/8"], "allowed_commands": ["curl"]}})
    with pytest.raises(ScopeViolationError):
        validator.validate_command(["rm", "-rf", "/"])

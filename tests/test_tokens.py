# tests/test_tokens.py
import os

import pytest

from prodanalytics_auth_library import ApiKeyValidator, tokens
from prodanalytics_auth_library.tokens import TokenStore


def write(path, text):
    """Replace the file the way the kubelet does: a new file swapped into place."""
    tmp = str(path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(tmp, path)


@pytest.fixture
def token_file(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    monkeypatch.setenv("PA_API_TOKENS_FILE", str(path))
    monkeypatch.setattr(tokens, "_default", None)  # fresh default store per test
    monkeypatch.setattr(tokens, "CHECK_INTERVAL_S", 0.0)
    return path


def store(path):
    return TokenStore(str(path), check_interval_s=0.0)


def test_falls_back_to_environment_when_file_missing(token_file, monkeypatch):
    monkeypatch.setenv("APITOKEN2", "from-env")
    s = store(token_file)
    assert s.current("APITOKEN2") == "from-env"
    assert s.is_valid("APITOKEN2", "from-env")
    assert not s.is_valid("APITOKEN2", "other")


def test_file_wins_over_environment(token_file, monkeypatch):
    monkeypatch.setenv("APITOKEN2", "from-env")
    write(token_file, "APITOKEN2=from-file\n")
    s = store(token_file)
    assert s.current("APITOKEN2") == "from-file"
    assert s.is_valid("APITOKEN2", "from-file")


def test_parses_quotes_comments_and_export(token_file):
    write(token_file, "# comment\nexport APITOKEN1='a b'\nAPITOKEN4=\"x=y\"\n\nBAD LINE\n")
    s = store(token_file)
    assert s.current("APITOKEN1") == "a b"
    assert s.current("APITOKEN4") == "x=y"


def test_hot_reload_picks_up_a_new_value_without_restart(token_file):
    write(token_file, "APITOKEN8=old\n")
    s = store(token_file)
    assert s.current("APITOKEN8") == "old"
    write(token_file, "APITOKEN8=new\n")
    assert s.current("APITOKEN8") == "new"
    assert not s.is_valid("APITOKEN8", "old")


def test_three_step_rotation_never_rejects_a_live_caller(token_file):
    s = store(token_file)
    write(token_file, "APITOKEN2=old\n")
    assert s.is_valid("APITOKEN2", "old")
    # Step 1: the new value is accepted before anyone sends it.
    write(token_file, "APITOKEN2=old\nAPITOKEN2_NEXT=new\n")
    assert s.current("APITOKEN2") == "old"
    assert s.is_valid("APITOKEN2", "old") and s.is_valid("APITOKEN2", "new")
    # Step 2: callers switch; the old value is still accepted.
    write(token_file, "APITOKEN2=new\nAPITOKEN2_PREVIOUS=old\n")
    assert s.current("APITOKEN2") == "new"
    assert s.is_valid("APITOKEN2", "old") and s.is_valid("APITOKEN2", "new")
    # Step 3: only the new value is left.
    write(token_file, "APITOKEN2=new\n")
    assert s.is_valid("APITOKEN2", "new")
    assert not s.is_valid("APITOKEN2", "old")


def test_keeps_last_values_while_file_is_briefly_missing(token_file):
    write(token_file, "APITOKEN5=kept\n")
    s = store(token_file)
    assert s.current("APITOKEN5") == "kept"
    os.remove(token_file)
    assert s.current("APITOKEN5") == "kept"


@pytest.mark.parametrize("presented", [None, "", "  "])
def test_blank_keys_are_rejected(token_file, presented):
    write(token_file, "APITOKEN1=secret\n")
    assert not store(token_file).is_valid("APITOKEN1", presented)


def test_unknown_token_name_accepts_nothing(token_file):
    write(token_file, "APITOKEN1=secret\n")
    assert not store(token_file).is_valid("APITOKEN99", "secret")


def test_check_interval_limits_rereads(token_file):
    write(token_file, "APITOKEN1=first\n")
    s = TokenStore(str(token_file), check_interval_s=3600)
    assert s.current("APITOKEN1") == "first"
    write(token_file, "APITOKEN1=second\n")
    assert s.current("APITOKEN1") == "first"  # not re-checked within the interval


def test_module_helpers_use_the_default_store(token_file):
    write(token_file, "APITOKEN12=v1\n")
    assert tokens.current_token("APITOKEN12") == "v1"
    assert tokens.token_is_valid("APITOKEN12", "v1")


def test_validator_accepts_previous_value_during_rotation(token_file):
    write(token_file, "APITOKEN5=new\nAPITOKEN5_PREVIOUS=old\n")
    validator = ApiKeyValidator()
    validator.logging_report = lambda *a: None
    assert validator.validate("Op", "Lease", "api", headers={"X-API-KEY": "old"})["statusType"] == "VALID"
    assert validator.validate("Op", "Lease", "api", headers={"X-API-KEY": "new"})["statusType"] == "VALID"
    with pytest.raises(ValueError, match="401003"):
        validator.validate("Op", "Lease", "api", headers={"X-API-KEY": "stale"})

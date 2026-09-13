from __future__ import annotations

import pytest

from secpilot.policy.scope import extract_targets, parse_target, target_in_scope


def test_parse_cidr_and_ip() -> None:
    assert parse_target("10.10.10.0/24").kind == "cidr"
    assert parse_target("10.10.10.24").ip == "10.10.10.24"
    assert parse_target("lab.example.com").hostname == "lab.example.com"


def test_in_scope(lab_scope) -> None:
    assert target_in_scope(parse_target("10.10.10.24"), lab_scope)
    assert target_in_scope(parse_target("lab.example.com"), lab_scope)
    assert not target_in_scope(parse_target("8.8.8.8"), lab_scope)


def test_extract_targets_from_query() -> None:
    text = "Find what is exposed on my lab server 10.10.10.24 and ignore 8.8.8.8"
    found = extract_targets(text)
    assert "10.10.10.24" in found
    assert "8.8.8.8" in found


def test_reject_garbage() -> None:
    with pytest.raises(ValueError):
        parse_target("not a host!!!")

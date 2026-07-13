#!/usr/bin/env python3
"""Offline tests for x402-verify-canary. No network. Run: python3 test_canary.py"""
import json
import sys

import x402_canary as c


def _codes(challenge):
    accepts, top = c.normalize(challenge)
    return [f.code for i, req in enumerate(accepts) for f in c.lint_requirement(i, req, top)]


def test_clean_v2_passes():
    ch = {
        "x402Version": 2,
        "resource": {"url": "https://x.io/a", "description": "CVE lookup"},
        "accepts": [{
            "scheme": "exact", "network": "eip155:8453", "maxAmountRequired": "2000",
            "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "payTo": "0xBEccE6dd106Cfa910F78fea188B2fcCEb73bdD0F",
            "resource": "https://x.io/a", "description": "CVE lookup",
        }],
    }
    assert _codes(ch) == ["clean"], _codes(ch)


def test_description_over_500_is_error():
    ch = {
        "x402Version": 2,
        "resource": {"url": "https://x.io/a", "description": "D" * 501},
        "accepts": [{
            "scheme": "exact", "network": "base", "maxAmountRequired": "2000",
            "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "payTo": "0xBEccE6dd106Cfa910F78fea188B2fcCEb73bdD0F",
            "resource": "https://x.io/a", "description": "ok",
        }],
    }
    codes = _codes(ch)
    assert "description-too-long" in codes, codes


def test_description_exactly_500_passes_length():
    ch = {
        "x402Version": 2,
        "resource": {"url": "https://x.io/a", "description": "D" * 500},
        "accepts": [{
            "scheme": "exact", "network": "base", "maxAmountRequired": "2000",
            "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "payTo": "0xBEccE6dd106Cfa910F78fea188B2fcCEb73bdD0F",
            "resource": "https://x.io/a", "description": "ok",
        }],
    }
    codes = _codes(ch)
    assert "description-too-long" not in codes, codes


def test_relative_resource_is_error():
    ch = {"x402Version": 1, "accepts": [{
        "scheme": "exact", "network": "base", "maxAmountRequired": "2000",
        "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        "payTo": "0xBEccE6dd106Cfa910F78fea188B2fcCEb73bdD0F",
        "resource": "GET /ledger/trial-balance", "description": "ok",
    }]}
    assert "resource-not-absolute" in _codes(ch), _codes(ch)


def test_missing_field_is_error():
    ch = {"x402Version": 1, "accepts": [{
        "scheme": "exact", "network": "base",
        "resource": "https://x.io/a", "description": "ok",
    }]}
    assert "missing-field" in _codes(ch), _codes(ch)


def test_interpret_verify():
    assert c.interpret_verify({"isValid": True})[0] == "green"
    assert c.interpret_verify({"isValid": False, "invalidReason": "insufficient_funds"})[0] == "green"
    assert c.interpret_verify({"isValid": False, "invalidReason": "resource.description too long"})[0] == "red"
    assert c.interpret_verify({"isValid": False, "invalidReason": "something novel"})[0] == "unknown"


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  ok   {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

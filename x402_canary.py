#!/usr/bin/env python3
"""
x402-verify-canary — catch silent x402 payment-acceptance regressions
before your payers do.

An x402 endpoint can quietly stop accepting valid payments. A facilitator
tightens a constraint, a description grows past a limit, a field changes
shape — and you don't find out until the payments stop. There is no error on
your side; the payers just disappear.

This canary is a smoke detector for that failure. It has two modes:

  lint    (no credentials, standard-library only)
          Fetch your endpoint's HTTP 402 challenge and check its payment
          requirements against the constraints real facilitators enforce —
          notably Coinbase CDP, whose /verify rejects a resource.description
          longer than 500 characters (see x402-foundation/x402#2832), and which
          catalogs the `resource` field, so it must be an absolute URL. Catches
          the known regression class with zero setup. CI-friendly (exit 1 on a
          hard finding).

  verify  (unfunded key, free + gasless)
          Build a well-formed payment for your endpoint's requirements, sign it
          with a throwaway key, and ask a facilitator's /verify whether it would
          be accepted. Because the key is unfunded and we only ever call /verify
          (never /settle), no USDC moves and nothing lands in your unique-payer
          metrics. A funds-related reject means the FORMAT is fine (green); a
          schema/format/length reject means your endpoint is being turned away
          before funds are even checked (red).

Built by the team behind VulnFeed and Ledger (https://novadyne.ai). MIT.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

# --- constraints real facilitators enforce (the intelligence this tool encodes) ---
# Coinbase CDP's hosted facilitator rejects a payment whose resource.description
# exceeds 500 characters. This is a hard, silent failure: verify returns invalid
# and the payer is turned away with no error on the seller side. Traced and pinned
# in x402-foundation/x402#2832 (the boundary is exactly 'a'*500 passes, 'a'*501
# rejects). Descriptions creep past this as sellers add detail — hence the canary.
CDP_MAX_DESCRIPTION = 500
WARN_DESCRIPTION = 450  # yellow: close enough that one more sentence trips it

# Fields required for the x402 "exact" scheme payment requirements.
REQUIRED_FIELDS = ("scheme", "network", "maxAmountRequired", "asset", "payTo", "resource")

# invalidReason substrings that mean "the format was accepted; only funding failed"
# (an unfunded canary key is EXPECTED to trip these — they are GREEN, not a defect).
FUNDING_REASONS = (
    "insufficient_funds",
    "insufficient funds",
    "insufficient_balance",
    "insufficient allowance",
    "insufficient_allowance",
    "balance",
)
# invalidReason substrings that mean the FORMAT was rejected — the regression (RED).
FORMAT_REASONS = (
    "description",
    "too long",
    "max",
    "length",
    "deserialize",
    "schema",
    "invalid_format",
    "does not match",
    "expected format",
    "unexpected",
    "malformed",
    "resource",
)


class Finding:
    def __init__(self, level: str, code: str, message: str):
        self.level = level  # "error" | "warn" | "ok"
        self.code = code
        self.message = message

    def as_dict(self):
        return {"level": self.level, "code": self.code, "message": self.message}


# ------------------------------------------------------------------ challenge --

def fetch_challenge(url: str, timeout: float = 15.0) -> dict:
    """GET the endpoint and return its parsed 402 challenge body.

    A well-behaved x402 endpoint answers an unpaid request with HTTP 402 and a
    JSON body carrying `accepts`. We deliberately send NO X-PAYMENT header, so
    nothing is ever charged.
    """
    req = urllib.request.Request(url, method="GET", headers={
        "Accept": "application/json",
        "User-Agent": "x402-verify-canary/0.1 (+https://github.com/novadyne-hq/x402-verify-canary)",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            # A 200 to an unpaid request means the endpoint served WITHOUT payment
            # (free tier, or a broken paywall). Surface it — it is its own problem.
            raise CanaryError(
                f"endpoint returned HTTP {resp.status} to an unpaid request "
                f"(expected 402). Either it has a free tier, or the paywall is "
                f"not gating this route. Body starts: {body[:200]!r}"
            )
    except urllib.error.HTTPError as e:
        if e.code != 402:
            body = e.read().decode("utf-8", "replace")
            raise CanaryError(f"expected HTTP 402, got {e.code}. Body: {body[:300]!r}")
        raw = e.read().decode("utf-8", "replace")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise CanaryError(f"402 challenge body was not JSON: {raw[:300]!r}")
    except urllib.error.URLError as e:
        raise CanaryError(f"could not reach {url}: {e}")


def normalize(challenge: dict) -> tuple[list[dict], dict | None]:
    """Return (accepts, top_resource) across x402 v1 and v2 challenge shapes.

    v2 carries a top-level `resource` OBJECT ({url, description, serviceName});
    v1 puts everything on each `accepts[]` entry. We keep both so the linter can
    check every place a description can live.
    """
    accepts = challenge.get("accepts") or []
    if not isinstance(accepts, list):
        raise CanaryError("challenge has no `accepts` array")
    top = challenge.get("resource")
    top = top if isinstance(top, dict) else None
    return accepts, top


# ---------------------------------------------------------------------- lint --

def _describe(where: str, value) -> list[Finding]:
    """Length-check a description field wherever it appears."""
    out = []
    if not isinstance(value, str):
        return out
    n = len(value)
    if n > CDP_MAX_DESCRIPTION:
        out.append(Finding(
            "error", "description-too-long",
            f"{where} is {n} chars (limit {CDP_MAX_DESCRIPTION}). CDP /verify will "
            f"REJECT payments for this endpoint — payers are turned away silently. "
            f"Trim it to ≤{CDP_MAX_DESCRIPTION}. (x402#2832)",
        ))
    elif n > WARN_DESCRIPTION:
        out.append(Finding(
            "warn", "description-near-limit",
            f"{where} is {n} chars — within {CDP_MAX_DESCRIPTION - n} of the "
            f"{CDP_MAX_DESCRIPTION}-char CDP limit. One more sentence trips it.",
        ))
    return out


def lint_requirement(idx: int, req: dict, top: dict | None) -> list[Finding]:
    findings: list[Finding] = []

    # 1. the headline regression: resource.description length (v2 top-level + per-accept)
    if top is not None:
        findings += _describe("resource.description", top.get("description"))
    findings += _describe(f"accepts[{idx}].description", req.get("description"))

    # 2. `resource` must be an ABSOLUTE url — CDP catalogs it at settle time; a
    #    relative path or a "METHOD /path" string indexes as a broken/unmatchable
    #    resource and never surfaces in discovery.
    resource = req.get("resource")
    if not isinstance(resource, str) or not resource:
        findings.append(Finding("error", "resource-missing",
                                f"accepts[{idx}].resource is missing/empty."))
    elif not (resource.startswith("http://") or resource.startswith("https://")):
        findings.append(Finding(
            "error", "resource-not-absolute",
            f"accepts[{idx}].resource = {resource!r} is not an absolute URL. CDP "
            f"catalogs this field; it must be the full https:// serving URL or the "
            f"listing is unmatchable in discovery.",
        ))

    # 3. required fields present
    for f in REQUIRED_FIELDS:
        if req.get(f) in (None, ""):
            findings.append(Finding("error", "missing-field",
                                    f"accepts[{idx}].{f} is missing."))

    # 4. shape sanity on the fields we can cheaply check
    asset = req.get("asset")
    if isinstance(asset, str) and asset and not _looks_like_evm_address(asset):
        findings.append(Finding("warn", "asset-shape",
                                f"accepts[{idx}].asset = {asset!r} does not look like "
                                f"a 0x EVM token address."))
    amt = req.get("maxAmountRequired")
    if amt is not None and not (isinstance(amt, str) and amt.isdigit()):
        findings.append(Finding("warn", "amount-shape",
                                f"accepts[{idx}].maxAmountRequired = {amt!r} should be a "
                                f"string of minor units (e.g. \"2000\" for 0.002 USDC)."))

    if not findings:
        findings.append(Finding("ok", "clean",
                                f"accepts[{idx}] ({req.get('scheme','?')}/"
                                f"{req.get('network','?')}) passes all checks."))
    return findings


def _looks_like_evm_address(s: str) -> bool:
    return (
        isinstance(s, str) and s.startswith("0x") and len(s) == 42
        and all(c in "0123456789abcdefABCDEF" for c in s[2:])
    )


def cmd_lint(args) -> int:
    challenge = fetch_challenge(args.url, timeout=args.timeout)
    accepts, top = normalize(challenge)
    all_findings: list[tuple[int, Finding]] = []
    for i, req in enumerate(accepts):
        for f in lint_requirement(i, req, top):
            all_findings.append((i, f))

    n_err = sum(1 for _, f in all_findings if f.level == "error")
    n_warn = sum(1 for _, f in all_findings if f.level == "warn")

    if args.json:
        print(json.dumps({
            "url": args.url,
            "x402Version": challenge.get("x402Version"),
            "accepts": len(accepts),
            "errors": n_err,
            "warnings": n_warn,
            "status": "red" if n_err else ("yellow" if n_warn else "green"),
            "findings": [f.as_dict() for _, f in all_findings],
        }, indent=2))
    else:
        icon = {"error": "✗", "warn": "⚠", "ok": "✓"}
        print(f"x402-verify-canary  →  {args.url}")
        print(f"  x402 version {challenge.get('x402Version','?')}, "
              f"{len(accepts)} payment requirement(s)\n")
        for _, f in all_findings:
            print(f"  {icon.get(f.level,'?')} [{f.code}] {f.message}")
        verdict = "RED — payments are (or will soon be) rejected" if n_err else (
                  "YELLOW — clean but close to a limit" if n_warn else
                  "GREEN — accepting payments")
        print(f"\n  {verdict}  ({n_err} error(s), {n_warn} warning(s))")
    return 1 if n_err else 0


# -------------------------------------------------------------------- verify --

def _network_to_cdp(network: str) -> str:
    """CDP's v1 payload names the network 'base' / 'base-sepolia'; challenges often
    carry the CAIP-2 form 'eip155:8453'. The EIP-3009 signature is chainId-bound,
    so this name translation is signature-safe."""
    n = (network or "").lower()
    return {
        "eip155:8453": "base",
        "base": "base",
        "eip155:84532": "base-sepolia",
        "base-sepolia": "base-sepolia",
    }.get(n, network)


def _chain_id(network: str) -> int:
    n = (network or "").lower()
    if ":" in n:
        try:
            return int(n.split(":", 1)[1])
        except ValueError:
            pass
    return {"base": 8453, "base-sepolia": 84532}.get(n, 8453)


def build_payment(req: dict, private_key: str) -> dict:
    """Build a canonical x402 v1 'exact' payment payload signed with `private_key`.

    Uses eth-account (EIP-712 TransferWithAuthorization, EIP-3009). The payload
    shape is the one CDP strictly validates:
        {x402Version:1, scheme:"exact", network:"base",
         payload:{signature, authorization:{from,to,value,validAfter,validBefore,nonce}}}
    """
    try:
        from eth_account import Account
        from eth_account.messages import encode_typed_data
    except ImportError:
        raise CanaryError(
            "verify mode needs `eth-account`. Install it (pip install eth-account) "
            "or run:  uv run --with eth-account x402_canary.py verify ...")
    import os
    import time

    acct = Account.from_key(private_key)
    asset = req["asset"]
    value = str(req.get("maxAmountRequired") or req.get("amount") or "0")
    now = int(time.time())
    valid_after = 0
    valid_before = now + int(req.get("maxTimeoutSeconds") or 300)
    nonce = "0x" + os.urandom(32).hex()

    extra = req.get("extra") or {}
    domain = {
        "name": extra.get("name", "USD Coin"),
        "version": str(extra.get("version", "2")),
        "chainId": _chain_id(req.get("network", "base")),
        "verifyingContract": asset,
    }
    types = {
        "TransferWithAuthorization": [
            {"name": "from", "type": "address"},
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "validAfter", "type": "uint256"},
            {"name": "validBefore", "type": "uint256"},
            {"name": "nonce", "type": "bytes32"},
        ],
    }
    message = {
        "from": acct.address,
        "to": req["payTo"],
        "value": int(value),
        "validAfter": valid_after,
        "validBefore": valid_before,
        "nonce": nonce,
    }
    signed = Account.sign_message(
        encode_typed_data(domain, types, message), private_key)
    return {
        "x402Version": 1,
        "scheme": req.get("scheme", "exact"),
        "network": _network_to_cdp(req.get("network", "base")),
        "payload": {
            "signature": "0x" + signed.signature.hex().removeprefix("0x"),
            "authorization": {
                "from": acct.address,
                "to": req["payTo"],
                "value": value,
                "validAfter": str(valid_after),
                "validBefore": str(valid_before),
                "nonce": nonce,
            },
        },
    }


def interpret_verify(resp: dict) -> tuple[str, str]:
    """Map a facilitator /verify response to (verdict, reason).

    verdict: 'green' (format accepted; only funding failed, expected for an
    unfunded key), 'red' (format rejected — the regression), or 'unknown'.
    """
    if resp.get("isValid") is True:
        return "green", "facilitator accepted the payment as valid"
    reason = str(resp.get("invalidReason") or resp.get("error") or resp.get("reason") or "")
    low = reason.lower()
    if any(k in low for k in FUNDING_REASONS):
        return "green", f"format accepted; only funding failed (expected, unfunded key): {reason}"
    if any(k in low for k in FORMAT_REASONS):
        return "red", f"FORMAT rejected before funds were checked: {reason}"
    return "unknown", f"could not classify facilitator response: {reason or resp}"


def cmd_verify(args) -> int:
    from eth_account import Account  # fail early with a clear message via build_payment

    challenge = fetch_challenge(args.url, timeout=args.timeout)
    accepts, _ = normalize(challenge)
    if not accepts:
        raise CanaryError("no payment requirements to probe")
    req = accepts[args.index]

    # a fresh, in-memory, UNFUNDED key — never persisted, never funded.
    key = args.key or ("0x" + __import__("os").urandom(32).hex())
    payment = build_payment(req, key)

    verify_url = args.facilitator_url.rstrip("/")
    if not verify_url.endswith("/verify"):
        verify_url += "/verify"
    body = json.dumps({
        "x402Version": 1,
        "paymentPayload": payment,
        "paymentRequirements": req,
    }).encode()
    headers = {"Content-Type": "application/json",
               "User-Agent": "x402-verify-canary/0.1"}
    for h in args.header or []:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()

    hreq = urllib.request.Request(verify_url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(hreq, timeout=args.timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {"error": raw[:500]}

    verdict, reason = interpret_verify(parsed)
    if args.json:
        print(json.dumps({"url": args.url, "facilitator": verify_url,
                          "verdict": verdict, "reason": reason,
                          "raw": parsed}, indent=2))
    else:
        icon = {"green": "✓", "red": "✗", "unknown": "?"}[verdict]
        print(f"x402-verify-canary  →  {args.url}")
        print(f"  facilitator: {verify_url}")
        print(f"  {icon} {verdict.upper()}: {reason}")
        print(f"\n  raw facilitator response: {json.dumps(parsed)}")
    return 0 if verdict == "green" else (1 if verdict == "red" else 2)


# ---------------------------------------------------------------------- main --

class CanaryError(Exception):
    pass


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="x402-verify-canary",
        description="Catch silent x402 payment-acceptance regressions before your payers do.")
    p.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout seconds")
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("lint", help="zero-credential static check of the 402 challenge")
    pl.add_argument("url", help="your x402 endpoint URL")
    pl.add_argument("--json", action="store_true", help="machine-readable output")
    pl.set_defaults(func=cmd_lint)

    pv = sub.add_parser("verify", help="unfunded-key live /verify probe (free, gasless)")
    pv.add_argument("url", help="your x402 endpoint URL")
    pv.add_argument("--facilitator-url", required=True,
                    help="facilitator base or /verify URL to probe (e.g. your CDP proxy)")
    pv.add_argument("--header", action="append",
                    help="extra request header 'Key: Value' (repeatable; e.g. auth)")
    pv.add_argument("--index", type=int, default=0,
                    help="which accepts[] entry to probe (default 0)")
    pv.add_argument("--key", help="private key to sign with (default: fresh unfunded key)")
    pv.add_argument("--json", action="store_true", help="machine-readable output")
    pv.set_defaults(func=cmd_verify)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except CanaryError as e:
        print(f"x402-verify-canary: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())

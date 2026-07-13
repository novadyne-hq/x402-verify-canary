# x402-verify-canary

**Catch silent x402 payment-acceptance regressions before your payers do.**

An [x402](https://github.com/x402-foundation/x402) endpoint can quietly stop
accepting valid payments. A facilitator tightens a constraint, a description
grows past a limit, a field changes shape — and you don't find out until the
payments stop. There is no error on your side; the payers just disappear.

This happens for real. In [x402-foundation/x402#2832](https://github.com/x402-foundation/x402/issues/2832),
Coinbase's CDP facilitator started rejecting any payment whose `resource.description`
was longer than **500 characters** — the boundary is exactly `'a'*500` passes,
`'a'*501` rejects. Endpoints that had been earning went to zero with nothing in
their own logs to explain it.

`x402-verify-canary` is a smoke detector for that failure class.

## Two modes

### `lint` — zero-credential, standard-library only

Fetch your endpoint's HTTP 402 challenge (sending **no** payment, so nothing is
ever charged) and check its payment requirements against the constraints real
facilitators enforce:

- **`resource.description` ≤ 500 chars** — the CDP regression above. Checked on
  both the top-level `resource` object (x402 v2) and each `accepts[]` entry.
- **`resource` is an absolute URL** — CDP catalogs this field at settle time; a
  relative path or a `"METHOD /path"` string indexes as an unmatchable resource
  and never surfaces in discovery.
- **required fields present** — `scheme`, `network`, `maxAmountRequired`,
  `asset`, `payTo`, `resource`.
- **shape sanity** — `asset` looks like a `0x` token address; `maxAmountRequired`
  is a string of minor units.

```console
$ x402_canary.py lint https://your-service.example/paid/endpoint
x402-verify-canary  →  https://your-service.example/paid/endpoint
  x402 version 2, 1 payment requirement(s)

  ✓ [clean] accepts[0] (exact/eip155:8453) passes all checks.

  GREEN — accepting payments  (0 error(s), 0 warning(s))
```

Exit code is **1** on any hard finding, so it drops straight into CI. Add
`--json` for machine-readable output.

### `verify` — unfunded-key live probe (free + gasless)

Build a well-formed payment for your endpoint's requirements, sign it with a
**throwaway, unfunded key**, and ask a facilitator's `/verify` whether it would
be accepted.

Because the key is unfunded and we only ever call `/verify` (never `/settle`),
**no USDC moves and nothing lands in your unique-payer metrics.** A funds-related
reject means the format is fine (green); a schema / format / length reject means
your endpoint is being turned away *before funds are even checked* (red).

```console
$ x402_canary.py verify https://your-service.example/paid/endpoint \
    --facilitator-url https://your-facilitator.example \
    --header "Authorization: Bearer $FACILITATOR_TOKEN"
```

`verify` needs [`eth-account`](https://pypi.org/project/eth-account/) for the
EIP-3009 `TransferWithAuthorization` signature. The simplest way to run it:

```console
$ uv run --with eth-account x402_canary.py verify <url> --facilitator-url <url>
```

Point `--facilitator-url` at whichever facilitator your endpoint settles through
(pass its auth with `--header`). The payment payload is built to the canonical
CDP `exact`-scheme shape (`{x402Version:1, scheme, network:"base", payload:{signature, authorization}}`),
and the raw facilitator response is always printed so you can judge anything the
tool classifies as `UNKNOWN`.

## Install

No install needed for `lint` — it's a single standard-library file:

```console
$ curl -O https://raw.githubusercontent.com/novadyne-hq/x402-verify-canary/main/x402_canary.py
$ python3 x402_canary.py lint <your-endpoint>
```

`verify` additionally needs `eth-account` (`pip install eth-account`, or use the
`uv run --with` line above).

## In CI

Run the linter against every priced endpoint on every deploy:

```yaml
- name: x402 payment-acceptance canary
  run: |
    curl -sO https://raw.githubusercontent.com/novadyne-hq/x402-verify-canary/main/x402_canary.py
    python3 x402_canary.py lint https://your-service.example/paid/endpoint
```

A red result fails the job before the regression reaches a payer.

## Why "unfunded key" and "verify only"

Two common ways to test a paywall are worse than they look:

- **Paying yourself** costs real USDC and pollutes your own unique-payer /
  revenue metrics with a self-payment — the exact signal you're trying to keep
  clean.
- **Sending a real payment from a funded key** can settle, which is the thing
  you're trying to avoid measuring.

An unfunded key that only reaches `/verify` sidesteps both: the facilitator
parses and validates the *shape* of your payment (which is where the regressions
live) without any on-chain movement. That's the whole trick.

## Limitations (honest scope)

- `lint` encodes the constraints we know about today (chiefly the CDP 500-char
  `resource.description` limit and the absolute-`resource` requirement). It is a
  known-regression detector, not a full x402 spec validator. PRs adding checks
  as facilitators publish new limits are welcome.
- `verify`'s green/red classification is a best-effort read of the facilitator's
  `invalidReason`; the raw response is always shown so you can override the call.
- The tool never funds a key, never settles, and never sends a payment header to
  your paid endpoint — it only reads the 402 challenge and talks to `/verify`.

## License

MIT — see [LICENSE](LICENSE).

---

Built by the team behind [VulnFeed](https://vulnfeed.novadyne.ai) and
[Ledger](https://ledger.novadyne.ai) at [Novadyne](https://novadyne.ai). We run
priced x402 endpoints ourselves; this is the canary we wanted.

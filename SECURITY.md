# Security policy

The issuer holds money: a Cashu wallet at the mint, the ecash it sells
over Lightning (x402), the per-server settlement ledger, and the signing
key that PIR servers trust. A bug that moves, mints or double-spends
value, lets a token be redeemed twice, or books gas to a server without
payment is the highest-priority vulnerability here.

## Reporting a vulnerability

Please do not open a public issue, pull request or discussion for a
security problem.

Report it privately through GitHub: **Security → Report a vulnerability**
on this repository
(<https://github.com/Bitcoin-PIR/issuer/security/advisories/new>).
The report reaches the maintainer only.

Include what you can: the affected component and commit or deployed
release, the steps or script that shows the problem, its impact, and
whether you ran it against the production issuer. Reproduce against a
local build where you can: `cargo test`, or `bpir-issuer serve` against a
local `cdk-mintd` and a regtest or signet Lightning node. Small purchases
of your own against the production issuer and mint are fine; do not try
to drain the float or degrade the service for others.

## What to expect

The project is maintained by one person.

- Acknowledgement within 7 days.
- An assessment and a fix plan within 30 days. Anything that can move
  funds or double-spend credits comes first and may be hot-fixed on the
  production host before a release.
- Coordinated disclosure: the fix ships with a GitHub advisory that
  credits you unless you ask otherwise. If a fix needs more than 90 days
  we agree a disclosure date with you.

## Scope

In scope:

- `bpir-issuer` (`src/`): credit redemption (`/v2/redeem`), the x402
  ecash sale (`/v2/x402/ecash`), the settlement ledger, the Cashu wallet
  handling and the issuer signing key.
- `bpir-cln-rpc-guard` (`cln-rpc-guard/`): the allowlisting proxy in
  front of the Core Lightning RPC socket. A way to reach a method it does
  not allow is a vulnerability.
- The systemd units and file layout in `deploy/`.
- The contract in the main repository's
  [`docs/CREDITS.md`](https://github.com/Bitcoin-PIR/Bitcoin-PIR/blob/main/docs/CREDITS.md):
  a disagreement between issuer and servers that credits gas without
  value.
- The production deployment on pir1 (issuer.bitcoinpir.org,
  mint.bitcoinpir.org) as described in the main repository's
  [`docs/SECURITY_POSTURE.md`](https://github.com/Bitcoin-PIR/Bitcoin-PIR/blob/main/docs/SECURITY_POSTURE.md).

Out of scope:

- Bugs in `cdk`, `cdk-mintd`, Core Lightning or Bitcoin Core themselves.
  Report those upstream, and tell us if they affect this deployment.
- Lightning network-level behaviour (routing, fees, channel policy).
- Volume denial of service against the rate-limited x402 endpoints.
- The PIR protocol, servers and browser client: report those to
  [Bitcoin-PIR/Bitcoin-PIR](https://github.com/Bitcoin-PIR/Bitcoin-PIR/security/advisories/new).

## Supported versions

Only the `main` branch and the release running on pir1 receive fixes.

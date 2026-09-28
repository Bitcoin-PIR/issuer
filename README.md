# BitcoinPIR issuer

The credit issuer for BitcoinPIR paid queries. A browser (or any client)
buys an ARC credential for a `cashuB…` token and spends it one credit at a
time on any PIR server; each server forwards what it was shown to the
issuer, which verifies it, rejects double spends, and settles with that
server in gas.

The contract this service implements is "Issuer API" in
[`docs/CREDITS.md`](https://github.com/Bitcoin-PIR/Bitcoin-PIR/blob/main/docs/CREDITS.md)
in the main repository. Its types (`pir-credit`) are consumed from that
repository by git revision, so issuer and servers can never disagree on
the bytes. The v1 session grants (`/v1/info`, `/v1/grants`) are retired.

## What it does

| Endpoint | Behaviour |
| --- | --- |
| `GET /v2/info` | the credits contract ([`docs/CREDITS.md`](https://github.com/Bitcoin-PIR/Bitcoin-PIR/blob/main/docs/CREDITS.md)): `credit_sat`, `gas_per_credit`, `base_gas_per_frame`, `egress_gas_per_mb`, `mints`, sat-priced `offers`, `rate_card` |
| `POST /v2/credentials` | pay one listed pack (`credits` = the presentation limit, `sat`) with a Cashu token and a blinded `arc::CredentialRequest`; the issuer swaps the token at the mint through a [cdk](https://crates.io/crates/cdk) wallet, blind-issues an ARC credential under the current epoch's key, and answers `CredentialResponseV2` (idempotent per token and request) |
| `POST /v2/redeem` | a PIR server forwards what a client presented (`RedeemRequestV1`, signed by the server's identity key and carrying its operator-signed certificate); the issuer verifies each item — a Cashu token is swapped at the mint (`gas_added = sats × gas_per_credit / credit_sat`), ARC presentations are verified under their epoch's key with a global tag set per epoch (`gas_per_credit` each, `402 double_spend` on reuse, `402 expired_epoch` outside the epoch or its grace) — books the value to that server, and answers `RedeemResponseV1` signed by the same key servers pin |
| `GET /healthz` | `ok` |

Rules that matter:

- **Never credit without money.** A credential is issued and a redemption
  booked only after the mint accepted the swap; a token the mint refuses
  gets `402 token_rejected`, a mint that cannot be reached gets
  `503 mint_unavailable` and the token stays spendable.
- **Idempotent per token.** The idempotency key is derived from the token's
  proof secrets; a token is spent at most once across all paths, and a
  repeated credential request for the same token and blinded request
  returns the same answer without consulting the mint.
- **Honest about the unknown.** If the process dies (or the mint times out)
  after the swap request was sent, the token is left in a `pending` state
  and logged at error level for manual reconciliation.
- **No secrets on the PIR hosts.** The issuer is the only component that
  holds the issuer signing seed, the ARC master seed, and the wallet seed.
  Servers pin the issuer public key with `--credit-issuer-pubkey`.
- **Redeem is authenticated and replay-safe.** Only servers certified by an
  operator key in `operator_pubkeys` may redeem; `server_id` must match the
  certificate; a repeated `(server_id, nonce)` returns the stored signed
  answer without touching the mint; a token that already bought something
  (a credential, or a v1 grant before the retirement) or was redeemed once
  answers `402 already_redeemed`. Every redemption is
  appended to `redeem.jsonl`, the per-server settlement ledger
  (`bpir-issuer settlement --config …`).

## Build

```sh
cargo build --release          # rust-toolchain.toml pins the compiler
cargo test
```

`cdk` is built with `default-features = false, features = ["wallet"]`; no
mint, nostr, or Lightning code is compiled in.

## Operate

```sh
# once: keys
bpir-issuer keygen --out /etc/bitcoinpir/issuer/grant.key      # issuer seed; prints the pubkey to pin
bpir-issuer wallet-seed --out /etc/bitcoinpir/issuer/wallet.seed

# config
cp config.example.toml /etc/bitcoinpir/issuer/config.toml       # edit mints, CORS, operator keys, [arc] packs

# run
bpir-issuer serve --config /etc/bitcoinpir/issuer/config.toml
bpir-issuer balance --config /etc/bitcoinpir/issuer/config.toml   # ecash held per (mint, unit)
bpir-issuer settlement --config /etc/bitcoinpir/issuer/config.toml # gas and sat redeemed per PIR server
bpir-issuer arc-seed --out /etc/bitcoinpir/issuer/arc.seed        # ARC master seed (per-epoch issuer keys)
bpir-issuer pubkey --key /etc/bitcoinpir/issuer/grant.key
bpir-issuer mnemonic --out /etc/bitcoinpir/mint/seed         # BIP39 phrase for a cdk-mintd --seed-file (mode 0400)
```

`deploy/bpir-issuer.service` is a hardened systemd unit; put a reverse
proxy or a Cloudflare tunnel in front (the browser pins
`https://issuer.bitcoinpir.org`). The service speaks plain HTTP and sends
the CORS headers the browser needs.

On every PIR server:

```sh
unified_server … --credit-issuer-url https://issuer.bitcoinpir.org \
                 --credit-issuer-pubkey /etc/bitcoinpir/issuer/grant.pub   # 64 hex chars from keygen
# what each backend charges: --require-credits and --access (docs/CREDITS.md "Access policy")
```

The issuer's `operator_pubkeys` must list the operator key that signed the
servers' identity certificates, or `POST /v2/redeem` refuses them.

### Files the operator owns

| File | Contents | Backup |
| --- | --- | --- |
| `grant.key` | 32-byte Ed25519 issuer seed (signs redeem answers) | yes — rotating it means re-pinning every server |
| `arc.seed` | 32-byte ARC master seed | yes — it is the credentials |
| `wallet.seed` | 64-byte Cashu wallet seed | yes — with the mint, it recovers the ecash |
| `wallet.sqlite` | proofs the issuer holds (cdk wallet store) | yes |
| `grants.jsonl` | append-only log: every token seen, what it bought, every failure (the name predates credits) | yes — it is the idempotency store and the reconciliation record |
| `redeem.jsonl` | every redemption per server | yes — it is the settlement ledger |

Money accumulates in the wallet as ecash. Melt it to Lightning with any cdk
wallet (for example `cdk-cli` with the same seed) or extend the `balance`
command; the issuer itself never pays out.

### Fees

A mint may deduct input fees on the swap, so the amount credited can be
below the token's face value. The issuer validates the **face value**
against the pack and absorbs the fee; the credited amount is recorded in
`grants.jsonl`.

## `bpir-cln-rpc-guard` (workspace member `cln-rpc-guard/`)

The issuer never opens the Core Lightning socket. For x402 (`exact/lnbtc`)
it needs three node calls, `invoice`, `listinvoices`, and `waitinvoice`, and it
gets exactly those through `bpir-cln-rpc-guard`: a proxy that runs in the node
socket's group, exposes a second Unix socket to the issuer's group, forwards a
request unchanged only if its method and named parameters pass the allowlist,
and answers everything else itself with a JSON-RPC error. Bounds (flags):
label prefix (default `bpir-x402-`, also required on the read calls, so the
mint's invoices stay out of reach), `amount_msat` range, `expiry` maximum,
`description` size, `deschashonly` must be `true` (description-hash invoices
only, no `preimage`, no `fallbacks`), `listinvoices` needs exactly one of
`label` / `payment_hash` / `invstring` (no unfiltered listing), an invoice rate
limit per minute, and a connection cap. Responses are copied back byte for byte.
Unit: `deploy/bpir-cln-rpc-guard.service` (`User=` its own account,
`SupplementaryGroups=` the node socket's group, `Group=` the issuer's group,
`UMask=0007`, socket `/run/bpir-cln-rpc-guard/rpc.sock`).

## Layout

```
src/config.rs   TOML config and validation, seed-file reader
src/cashu.rs    token summary, idempotency key, Swapper trait, cdk implementation
src/issuer_key.rs  the Ed25519 key that signs redeem answers
src/arc.rs      ARC credential issuance and presentation verification
src/redeem.rs   POST /v2/redeem verification, replay index, settlement ledger
src/store.rs    JSON-lines idempotency/audit store
src/api.rs      axum router, handlers, contract error codes
src/main.rs     CLI
tests/api.rs    contract tests with a scripted fake mint
```

License: MIT OR Apache-2.0.

# BitcoinPIR issuer

The credit issuer for BitcoinPIR paid queries. Cashu ecash is the only
credit. The issuer keeps a Cashu wallet at the mint; a client presents a
`cashuB…` token to any PIR server, the server forwards it to the issuer
(`POST /v2/redeem`), and the issuer swaps it into that wallet and books
its value to the server's settlement ledger in gas. The issuer also sells
ecash from the wallet for Lightning (x402 `exact/lnbtc`,
`POST /v2/x402/ecash`).

The contract this service implements is "Issuer API" in
[`docs/CREDITS.md`](https://github.com/Bitcoin-PIR/Bitcoin-PIR/blob/main/docs/CREDITS.md)
in the main repository. Its types (`pir-credit`) are consumed from that
repository by git revision, so issuer and servers can never disagree on
the bytes. The v1 session grants (`/v1/info`, `/v1/grants`) are retired,
and so are the ARC credentials (`POST /v2/credentials`, presentation
kind 2): `/v2/redeem` refuses kind 2 with `400 unsupported_kind`, a config
that still has an `[arc]` table fails to load, and `arc.seed` is no longer
read (keeping or deleting the file is the operator's call).

## What it does

| Endpoint | Behaviour |
| --- | --- |
| `GET /v2/info` | the credits contract ([`docs/CREDITS.md`](https://github.com/Bitcoin-PIR/Bitcoin-PIR/blob/main/docs/CREDITS.md)): `credit_sat`, `gas_per_credit`, `base_gas_per_frame`, `egress_gas_per_mb`, `mints`, `rate_card`; `offers` is empty (nothing is sold up front) |
| `POST /v2/redeem` | a PIR server forwards what a client presented (`RedeemRequestV1`, signed by the server's identity key and carrying its operator-signed certificate); the issuer swaps each Cashu token (kind 1) into its wallet at the mint through a [cdk](https://crates.io/crates/cdk) wallet (`gas_added = sats × gas_per_credit / credit_sat`), books the value to that server, and answers `RedeemResponseV1` signed by the same key servers pin |
| `POST /v2/x402/ecash` | with an `[x402]` table: sells Cashu ecash from the wallet for a Lightning payment (below); `GET /v2/x402/invoices/{payment_hash}` reports the state of a challenge invoice |
| `GET /healthz` | `ok` |

Rules that matter:

- **Never credit without money.** A redemption is booked only after the
  mint accepted the swap; a token the mint refuses
  gets `402 token_rejected`, a mint that cannot be reached gets
  `503 mint_unavailable` and the token stays spendable.
- **Idempotent per token.** The idempotency key is derived from the token's
  proof secrets; a token is spent at most once across all paths.
- **Honest about the unknown.** If the process dies (or the mint times out)
  after the swap request was sent, the token is left in a `pending` state
  and logged at error level for manual reconciliation.
- **No secrets on the PIR hosts.** The issuer is the only component that
  holds the issuer signing seed and the wallet seed.
  Servers pin the issuer public key with `--credit-issuer-pubkey`.
- **Redeem is authenticated and replay-safe.** Only servers certified by an
  operator key in `operator_pubkeys` may redeem; `server_id` must match the
  certificate; a repeated `(server_id, nonce)` returns the stored signed
  answer without touching the mint; a token that already bought something
  (an ARC credential or a v1 grant, before their retirement) or was
  redeemed once answers `402 already_redeemed`. Every redemption is
  appended to `redeem.jsonl`, the per-server settlement ledger
  (`bpir-issuer settlement --config …`).

## Build

```sh
cargo build --release          # rust-toolchain.toml pins the compiler
cargo test
```

`cdk` is built with `default-features = false, features = ["wallet"]`; no
mint, nostr, or Lightning code is compiled into the binary. `tests/mint.rs`
runs the ecash sale against an in-process cdk mint (a dev-dependency whose
signatory compiles gRPC code), so `cargo test` needs `protoc`.

## Operate

```sh
# once: keys
bpir-issuer keygen --out /etc/bitcoinpir/issuer/grant.key      # issuer seed; prints the pubkey to pin
bpir-issuer wallet-seed --out /etc/bitcoinpir/issuer/wallet.seed

# config
cp config.example.toml /etc/bitcoinpir/issuer/config.toml       # edit mints, CORS, operator keys, [x402]

# run
bpir-issuer serve --config /etc/bitcoinpir/issuer/config.toml
bpir-issuer balance --config /etc/bitcoinpir/issuer/config.toml   # ecash held per (mint, unit)
bpir-issuer settlement --config /etc/bitcoinpir/issuer/config.toml # gas and sat redeemed per PIR server
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
| `wallet.seed` | 64-byte Cashu wallet seed | yes — with the mint, it recovers the ecash |
| `wallet.sqlite` | proofs the issuer holds (cdk wallet store) | yes |
| `grants.jsonl` | append-only log: every token seen, what it bought, every failure (the name predates credits) | yes — it is the idempotency store and the reconciliation record |
| `redeem.jsonl` | every redemption per server | yes — it is the settlement ledger |

Money accumulates in the wallet as ecash. Melt it to Lightning with any cdk
wallet (for example `cdk-cli` with the same seed) or extend the `balance`
command; the issuer itself never pays out.

### Fees

A mint may deduct input fees on the swap, so the amount credited can be
below the token's face value. `/v2/redeem` books what the mint actually
credited (recorded in `grants.jsonl`); an ecash sale spends `sat` plus the
input fee of its inputs, and the issuer absorbs that fee.

## x402 `exact/lnbtc` (Lightning) purchase rail

With a `[x402]` table (`config.example.toml`), `POST /v2/x402/ecash`
accepts the x402 flow (x402-foundation/x402
`specs/schemes/exact/scheme_exact_lnbtc.md`, merged 2026-09-23; HTTP
transport `specs/transports-v2/http.md`):

1. A request without `PAYMENT-SIGNATURE` is answered `402` with
   `PAYMENT-REQUIRED` (base64 `PaymentRequired`, also the JSON body):
   scheme `exact`, network
   `lnbtc:000000000019d6689c085ae165831e93`, `amount` in millisatoshi,
   `payTo` = the node key, `extra.invoice` = a fresh BOLT11 whose description
   hash is the `http:1` request hash (JCS of method, URL, body hash, and the
   bound headers), `extra.requestHash`, profile, and params.
2. The client pays and retries the byte-identical request with
   `PAYMENT-SIGNATURE` (base64 `PaymentPayload` carrying `payload.preimage`).
   The issuer recomputes the binding from the actual request, runs the
   facilitator checks (accepted terms, strict BOLT11 decode, payee =
   `payTo`, description hash = request hash, preimage = payment hash,
   paid-but-expired window), records `x402:<network>:<payment_hash>` in the
   store (its replay entry: a second claim is `duplicate_settlement`, an
   identical retry replays the answer), and answers with
   `PAYMENT-RESPONSE` (`transaction` = payment hash, no `payer`).
3. A human can pay the same invoice from a phone: `GET
   /v2/x402/invoices/{payment_hash}` reports `unpaid` / `paid` / `expired`
   and, once paid, the preimage, so the browser finishes step 2 unchanged.
   Only invoices with the x402 label prefix are visible.

Fresh invoices are limited per client address and globally. Money lands in
the node's channel balance (not in the Cashu wallet); `bpir-issuer
settlement` is unaffected.

### Ecash: `POST /v2/x402/ecash`

The rail sells plain Cashu ecash from the issuer's wallet (first mint
in `mints`). The body is `{"sat": 1000, "outputs": [{"amount": 8, "id":
"<keyset id>", "B_": "<66 hex>"}, …]}`: 1 to 256 NUT-00 blinded outputs of
the mint's active `sat` keyset, powers of two it signs, distinct `B_`,
summing to `sat` within `[x402] ecash_min_sat`..`ecash_max_sat` (defaults 10
and 20000); anything else is `400 invalid_request`.

1. Without `PAYMENT-SIGNATURE`: the `402` challenge above for `sat × 1000`
   msat, bound to this path and body, or `503 float_exhausted` when the
   wallet cannot cover `sat` plus the mint's input fee.
2. The paid, byte-identical retry settles as above. The issuer records
   `x402_ecash_pending` under the payment, reserves proofs worth exactly
   `sat` plus their input fee (one ordinary wallet swap makes change first
   when it lacks the denominations), swaps them at the mint into exactly the
   client's outputs, records `x402_ecash_issued`, and answers
   `{"signatures": [{"amount", "id", "C_", "dleq": {"e", "s"}}, …]}` (NUT-00
   blind signatures with NUT-12 DLEQ, in output order) with
   `PAYMENT-RESPONSE`. The client unblinds them; the issuer never sees the
   proofs it sold. An identical retry replays the stored signatures.
3. If the mint cannot be reached or the outcome is unknown after settlement,
   the answer is `503 retry` and the record stays pending (the reserved
   inputs stay pending in the wallet). The next identical retry asks the
   mint first (NUT-09 restore): outputs it already signed are answered and
   the inputs marked spent; otherwise the inputs are checked (NUT-07) and the
   swap is made again.

Sales draw down the Cashu wallet (`bpir-issuer balance`); keep it topped up.

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
src/ecash.rs    x402 ecash sale: request checks, EcashSeller trait, cdk implementation
src/issuer_key.rs  the Ed25519 key that signs redeem answers
src/redeem.rs   POST /v2/redeem verification, replay index, settlement ledger
src/store.rs    JSON-lines idempotency/audit store
src/api.rs      axum router, handlers, contract error codes
src/main.rs     CLI
tests/api.rs    contract tests with a scripted fake mint
tests/mint.rs   ecash sales against an in-process cdk mint
```

License: MIT OR Apache-2.0.

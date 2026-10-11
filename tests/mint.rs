//! The `cdk` side of ecash sales ([`CdkSeller`]) against an in-process cdk
//! 0.18 mint with a fake Lightning backend: the issuer's wallet sells into
//! outputs a client blinds with cdk's own helpers, and the client unblinds
//! them into valid, unspent proofs. Nothing here touches the network.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bpir_issuer::ecash::{
    check, CdkSeller, EcashRequest, EcashSeller, RequestedOutput, SaleKeyset, SellError,
};
use cdk::amount::{FeeAndAmounts, SplitTarget};
use cdk::dhke::construct_proofs;
use cdk::mint::{Mint, MintBuilder, MintInput, MintMeltLimits, QuoteId};
use cdk::mint_url::MintUrl;
use cdk::nuts::nut00::{KnownMethod, ProofsMethods};
use cdk::nuts::{
    BatchCheckMintQuoteRequest, BatchMintRequest, BlindSignature, BlindedMessage,
    CheckStateRequest, CheckStateResponse, CurrencyUnit, Id, KeySet, Keys, KeysetResponse,
    MeltRequest, MintInfo, MintQuoteBolt11Request, MintQuoteBolt11Response, MintQuoteState,
    MintRequest, MintResponse, PaymentMethod, PreMintSecrets, Proofs, RestoreRequest,
    RestoreResponse, State, SwapRequest, SwapResponse,
};
use cdk::types::{FeeReserve, QuoteTTL};
use cdk::wallet::types::ProofInfo;
use cdk::wallet::{
    AuthWallet, LnurlPayInvoiceResponse, LnurlPayResponse, MintConnector, Wallet, WalletBuilder,
};
use cdk::{
    Amount, Error, MeltQuoteCreateResponse, MeltQuoteRequest, MeltQuoteResponse, MintQuoteRequest,
    MintQuoteResponse,
};
use cdk_fake_wallet::FakeWallet;

const MINT_URL: &str = "https://mint.test";

/// A `MintConnector` that calls the in-process mint directly. It counts
/// swaps, and can drop the next swap's answer after the mint processed it
/// (`lose`) or before the mint saw it (`drop`).
#[derive(Debug)]
struct Direct {
    mint: Mint,
    swaps: AtomicU64,
    lose: AtomicBool,
    drop: AtomicBool,
}

fn unsupported() -> Error {
    Error::Custom("not used by the issuer".into())
}

#[async_trait::async_trait]
impl MintConnector for Direct {
    async fn fetch_lnurl_pay_request(&self, _: &str) -> Result<LnurlPayResponse, Error> {
        Err(unsupported())
    }
    async fn fetch_lnurl_invoice(&self, _: &str) -> Result<LnurlPayInvoiceResponse, Error> {
        Err(unsupported())
    }
    async fn get_mint_keys(&self) -> Result<Vec<KeySet>, Error> {
        Ok(self.mint.pubkeys().keysets)
    }
    async fn get_mint_keyset(&self, keyset_id: Id) -> Result<KeySet, Error> {
        self.mint
            .keyset_pubkeys(&keyset_id)?
            .keysets
            .into_iter()
            .next()
            .ok_or(Error::UnknownKeySet)
    }
    async fn get_mint_keysets(&self) -> Result<KeysetResponse, Error> {
        Ok(self.mint.keysets())
    }
    async fn post_mint_quote(
        &self,
        _: MintQuoteRequest,
    ) -> Result<MintQuoteResponse<String>, Error> {
        Err(unsupported())
    }
    async fn post_mint(
        &self,
        _: &PaymentMethod,
        _: MintRequest<String>,
    ) -> Result<MintResponse, Error> {
        Err(unsupported())
    }
    async fn post_batch_check_mint_quote_status(
        &self,
        _: &PaymentMethod,
        _: BatchCheckMintQuoteRequest<String>,
    ) -> Result<Vec<MintQuoteResponse<String>>, Error> {
        Err(unsupported())
    }
    async fn post_batch_mint(
        &self,
        _: &PaymentMethod,
        _: BatchMintRequest<String>,
    ) -> Result<MintResponse, Error> {
        Err(unsupported())
    }
    async fn post_melt_quote(
        &self,
        _: MeltQuoteRequest,
    ) -> Result<MeltQuoteCreateResponse<String>, Error> {
        Err(unsupported())
    }
    async fn get_mint_quote_status(
        &self,
        _: PaymentMethod,
        _: &str,
    ) -> Result<MintQuoteResponse<String>, Error> {
        Err(unsupported())
    }
    async fn get_melt_quote_status(
        &self,
        _: PaymentMethod,
        _: &str,
    ) -> Result<MeltQuoteResponse<String>, Error> {
        Err(unsupported())
    }
    async fn post_melt(
        &self,
        _: &PaymentMethod,
        _: MeltRequest<String>,
    ) -> Result<MeltQuoteResponse<String>, Error> {
        Err(unsupported())
    }
    async fn post_swap(&self, request: SwapRequest) -> Result<SwapResponse, Error> {
        self.swaps.fetch_add(1, Ordering::SeqCst);
        if self.drop.swap(false, Ordering::SeqCst) {
            return Err(Error::HttpError(None, "connection refused".into()));
        }
        let response = self.mint.process_swap_request(request).await?;
        if self.lose.swap(false, Ordering::SeqCst) {
            return Err(Error::HttpError(None, "connection reset".into()));
        }
        Ok(response)
    }
    async fn get_mint_info(&self) -> Result<MintInfo, Error> {
        self.mint.mint_info().await
    }
    async fn post_check_state(
        &self,
        request: CheckStateRequest,
    ) -> Result<CheckStateResponse, Error> {
        self.mint.check_state(&request).await
    }
    async fn post_restore(&self, request: RestoreRequest) -> Result<RestoreResponse, Error> {
        self.mint.restore(request).await
    }
    async fn get_auth_wallet(&self) -> Option<AuthWallet> {
        None
    }
    async fn set_auth_wallet(&self, _: Option<AuthWallet>) {}
}

/// A started mint for `sat` with a fake Lightning backend that pays every
/// invoice at once.
async fn start_mint(input_fee_ppk: u64) -> Mint {
    let db = Arc::new(cdk_sqlite::mint::memory::empty().await.unwrap());
    let mut builder = MintBuilder::new(db.clone());
    let backend = FakeWallet::new(
        FeeReserve {
            min_fee_reserve: 1.into(),
            percent_fee_reserve: 1.0,
        },
        HashMap::new(),
        HashSet::new(),
        0,
        CurrencyUnit::Sat,
    );
    builder
        .add_payment_processor(
            CurrencyUnit::Sat,
            PaymentMethod::Known(KnownMethod::Bolt11),
            MintMeltLimits::new(1, 1_000_000),
            Arc::new(backend),
        )
        .await
        .unwrap();
    builder
        .set_unit_fee(&CurrencyUnit::Sat, input_fee_ppk)
        .unwrap();
    let mint = builder
        .with_name("test mint".into())
        .with_description("in-process mint".into())
        .with_urls(vec![MINT_URL.into()])
        .build_with_seed(db, &[7u8; 64])
        .await
        .unwrap();
    mint.set_quote_ttl(QuoteTTL::new(10_000, 10_000))
        .await
        .unwrap();
    mint.start().await.unwrap();
    mint
}

fn active(mint: &Mint) -> (Id, Keys) {
    let id = mint.get_active_keysets()[&CurrencyUnit::Sat];
    let keys = mint.keyset_pubkeys(&id).unwrap().keysets[0].keys.clone();
    (id, keys)
}

fn fee_and_amounts(keys: &Keys) -> FeeAndAmounts {
    (0, keys.iter().map(|(amount, _)| amount.to_u64()).collect()).into()
}

/// Proofs of exactly `amounts`, bought at the mint through a paid quote.
async fn mint_proofs(mint: &Mint, amounts: &[u64]) -> Proofs {
    let total: u64 = amounts.iter().sum();
    let quote: MintQuoteBolt11Response<String> = mint
        .get_mint_quote(
            MintQuoteBolt11Request {
                amount: Amount::from(total),
                unit: CurrencyUnit::Sat,
                description: None,
                pubkey: None,
            }
            .into(),
        )
        .await
        .unwrap()
        .into();
    loop {
        let state: MintQuoteBolt11Response<String> = mint
            .check_mint_quotes(&[QuoteId::from_str(&quote.quote).unwrap()])
            .await
            .unwrap()[0]
            .clone()
            .into();
        if state.state == MintQuoteState::Paid {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (id, keys) = active(mint);
    let split = SplitTarget::Values(amounts.iter().map(|a| Amount::from(*a)).collect());
    let premint =
        PreMintSecrets::random(id, Amount::from(total), &split, &fee_and_amounts(&keys)).unwrap();
    let request = MintRequest {
        quote: quote.quote,
        outputs: premint.blinded_messages(),
        signature: None,
    };
    let response = mint
        .process_mint_request(MintInput::Single(request.try_into().unwrap()))
        .await
        .unwrap();
    construct_proofs(response.signatures, premint.rs(), premint.secrets(), &keys).unwrap()
}

struct Setup {
    mint: Mint,
    direct: Arc<Direct>,
    wallet: Wallet,
    seller: CdkSeller,
}

/// The issuer's wallet over the in-process mint, holding proofs of exactly
/// `float` (the denominations the sale has to work with).
async fn setup(input_fee_ppk: u64, float: &[u64]) -> Setup {
    let mint = start_mint(input_fee_ppk).await;
    let direct = Arc::new(Direct {
        mint: mint.clone(),
        swaps: AtomicU64::new(0),
        lose: AtomicBool::new(false),
        drop: AtomicBool::new(false),
    });
    let localstore = Arc::new(cdk_sqlite::wallet::memory::empty().await.unwrap());
    let mint_url = MintUrl::from_str(MINT_URL).unwrap();
    let wallet = WalletBuilder::new()
        .mint_url(mint_url.clone())
        .unit(CurrencyUnit::Sat)
        .localstore(localstore)
        .seed([9u8; 64])
        .shared_client(direct.clone())
        .build()
        .unwrap();
    wallet
        .localstore
        .add_mint(mint_url.clone(), None)
        .await
        .unwrap();
    let held = mint_proofs(&mint, float)
        .await
        .into_iter()
        .map(|p| ProofInfo::new(p, mint_url.clone(), State::Unspent, CurrencyUnit::Sat).unwrap())
        .collect();
    wallet.localstore.update_proofs(held, vec![]).await.unwrap();
    let seller = CdkSeller::new(wallet.clone(), Duration::from_secs(10));
    Setup {
        mint,
        direct,
        wallet,
        seller,
    }
}

/// What a client sends: outputs for `sat` blinded with fresh secrets, kept
/// with their secrets and blinding factors.
fn client_outputs(mint: &Mint, sat: u64) -> (PreMintSecrets, Vec<BlindedMessage>) {
    let (id, keys) = active(mint);
    let premint = PreMintSecrets::random(
        id,
        Amount::from(sat),
        &SplitTarget::None,
        &fee_and_amounts(&keys),
    )
    .unwrap();
    let request = EcashRequest {
        sat,
        outputs: premint
            .blinded_messages()
            .iter()
            .map(|o| RequestedOutput {
                amount: o.amount.to_u64(),
                id: o.keyset_id.to_string(),
                blinded_secret: o.blinded_secret.to_hex(),
            })
            .collect(),
    };
    let keyset = SaleKeyset {
        id,
        amounts: keys.iter().map(|(a, _)| a.to_u64()).collect(),
        input_fee_ppk: 0,
    };
    let outputs = check(&request, &keyset, 1, 1_000_000).unwrap();
    (premint, outputs)
}

/// The client's side: unblind, verify the DLEQ proofs, and check the proofs
/// are unspent at the mint by spending them in a swap of its own.
async fn redeem(mint: &Mint, premint: &PreMintSecrets, signatures: Vec<BlindSignature>) -> u64 {
    let (id, keys) = active(mint);
    let proofs = construct_proofs(signatures, premint.rs(), premint.secrets(), &keys).unwrap();
    for proof in &proofs {
        proof
            .verify_dleq(keys.amount_key(proof.amount).unwrap())
            .unwrap();
    }
    let states = mint
        .check_state(&CheckStateRequest {
            ys: proofs.ys().unwrap(),
        })
        .await
        .unwrap();
    assert!(states.states.iter().all(|s| s.state == State::Unspent));
    let value = proofs.total_amount().unwrap().to_u64();
    let fee = mint.get_proofs_fee(&proofs).await.unwrap().total.to_u64();
    let fresh = PreMintSecrets::random(
        id,
        Amount::from(value - fee),
        &SplitTarget::None,
        &fee_and_amounts(&keys),
    )
    .unwrap();
    mint.process_swap_request(SwapRequest::new(proofs, fresh.blinded_messages()))
        .await
        .unwrap();
    value
}

async fn in_flight(wallet: &Wallet) -> usize {
    wallet
        .get_proofs_by_states(vec![State::Reserved, State::Pending])
        .await
        .unwrap()
        .len()
}

#[tokio::test]
async fn sells_exact_inputs_and_makes_change_when_needed() {
    let s = setup(0, &[1024, 128, 64, 8, 2]).await;
    let keyset = s.seller.keyset().await.unwrap();
    assert_eq!(keyset.id, active(&s.mint).0);
    assert_eq!(keyset.input_fee_ppk, 0);
    assert_eq!(s.seller.spendable().await.unwrap(), 1226);

    // 10 = 8 + 2: the wallet holds those, one swap.
    let (premint, outputs) = client_outputs(&s.mint, 10);
    let signatures = s.seller.sell("sale-1", 10, &outputs).await.unwrap();
    assert_eq!(s.direct.swaps.load(Ordering::SeqCst), 1);
    assert_eq!(signatures.len(), outputs.len());
    for (signature, output) in signatures.iter().zip(&outputs) {
        assert_eq!(signature.amount, output.amount);
        assert!(signature.dleq.is_some());
    }
    // The mint restores the same signatures.
    let restored = s.seller.restore("sale-1", &outputs).await.unwrap().unwrap();
    assert_eq!(restored, signatures);
    assert_eq!(redeem(&s.mint, &premint, signatures).await, 10);
    assert_eq!(s.seller.spendable().await.unwrap(), 1216);
    assert_eq!(in_flight(&s.wallet).await, 0);

    // 1000 = 512+256+128+64+32+8: change from the 1024 first, then the sale.
    let (premint, outputs) = client_outputs(&s.mint, 1000);
    let signatures = s.seller.sell("sale-2", 1000, &outputs).await.unwrap();
    assert_eq!(s.direct.swaps.load(Ordering::SeqCst), 3);
    assert_eq!(redeem(&s.mint, &premint, signatures).await, 1000);
    assert_eq!(s.seller.spendable().await.unwrap(), 216);
    assert_eq!(in_flight(&s.wallet).await, 0);

    // More than the float: nothing reserved, nothing sent.
    let (_, outputs) = client_outputs(&s.mint, 300);
    assert!(matches!(
        s.seller.sell("sale-3", 300, &outputs).await,
        Err(SellError::Float(_))
    ));
    assert_eq!(s.direct.swaps.load(Ordering::SeqCst), 3);
    assert_eq!(s.seller.spendable().await.unwrap(), 216);
    assert_eq!(in_flight(&s.wallet).await, 0);
}

#[tokio::test]
async fn a_lost_answer_stays_pending_until_restore_settles_it() {
    let s = setup(0, &[16, 8, 2]).await;
    let (premint, outputs) = client_outputs(&s.mint, 10);
    s.direct.lose.store(true, Ordering::SeqCst);
    assert!(matches!(
        s.seller.sell("sale", 10, &outputs).await,
        Err(SellError::Unknown(_))
    ));
    // The inputs (8 + 2) wait as pending; the rest stays spendable.
    assert_eq!(
        s.wallet
            .get_pending_proofs()
            .await
            .unwrap()
            .total_amount()
            .unwrap(),
        Amount::from(10)
    );
    assert_eq!(s.seller.spendable().await.unwrap(), 16);

    // Selling again settles the spent inputs, but the mint will not sign the
    // outputs twice; the fresh inputs go back to the wallet.
    assert_eq!(
        s.seller.sell("sale", 10, &outputs).await,
        Err(SellError::AlreadySigned)
    );
    assert_eq!(in_flight(&s.wallet).await, 0);
    // Restore finds the signatures.
    let signatures = s.seller.restore("sale", &outputs).await.unwrap().unwrap();
    assert_eq!(in_flight(&s.wallet).await, 0);
    assert_eq!(s.seller.spendable().await.unwrap(), 16);
    assert_eq!(redeem(&s.mint, &premint, signatures).await, 10);
}

#[tokio::test]
async fn a_swap_the_mint_never_saw_is_sent_again() {
    let s = setup(0, &[8, 2]).await;
    let (premint, outputs) = client_outputs(&s.mint, 10);
    s.direct.drop.store(true, Ordering::SeqCst);
    assert!(matches!(
        s.seller.sell("sale", 10, &outputs).await,
        Err(SellError::Unknown(_))
    ));
    assert_eq!(in_flight(&s.wallet).await, 2);
    // Nothing signed; the retry finds the inputs unspent and sells.
    assert_eq!(s.seller.restore("sale", &outputs).await.unwrap(), None);
    let signatures = s.seller.sell("sale", 10, &outputs).await.unwrap();
    assert_eq!(in_flight(&s.wallet).await, 0);
    assert_eq!(s.seller.spendable().await.unwrap(), 0);
    assert_eq!(redeem(&s.mint, &premint, signatures).await, 10);
}

#[tokio::test]
async fn input_fees_are_paid_by_the_inputs() {
    // 1 sat per input: 10 sat of outputs take inputs 8 + 4 (two inputs, 2 sat).
    let s = setup(1000, &[64, 8, 2, 1]).await;
    let keyset = s.seller.keyset().await.unwrap();
    assert_eq!(keyset.input_fee_ppk, 1000);
    let (premint, outputs) = client_outputs(&s.mint, 10);
    let signatures = s.seller.sell("sale", 10, &outputs).await.unwrap();
    assert_eq!(redeem(&s.mint, &premint, signatures).await, 10);
    assert_eq!(in_flight(&s.wallet).await, 0);
    // 75 held: the change swap turned the 64 into 63 (one input, 1 sat), and
    // the sale spent 8 + 4 = 12 for 10 sat of outputs (two inputs, 2 sat).
    assert_eq!(s.seller.spendable().await.unwrap(), 75 - 1 - 12);
}

#[tokio::test]
async fn inputs_spent_behind_the_wallet_are_dropped_and_replaced_once() {
    let s = setup(0, &[8, 2, 16]).await;
    // Someone with the wallet seed spends the 8 and the 2 elsewhere.
    let stale: Proofs = s
        .wallet
        .get_unspent_proofs()
        .await
        .unwrap()
        .into_iter()
        .filter(|p| p.amount != Amount::from(16))
        .collect();
    let (id, keys) = active(&s.mint);
    let elsewhere = PreMintSecrets::random(
        id,
        Amount::from(10),
        &SplitTarget::None,
        &fee_and_amounts(&keys),
    )
    .unwrap();
    s.mint
        .process_swap_request(SwapRequest::new(stale, elsewhere.blinded_messages()))
        .await
        .unwrap();

    // The sale picks them, learns they are spent, drops them, makes change
    // from the 16, and sells.
    let (premint, outputs) = client_outputs(&s.mint, 10);
    let signatures = s.seller.sell("sale", 10, &outputs).await.unwrap();
    assert_eq!(redeem(&s.mint, &premint, signatures).await, 10);
    assert_eq!(s.direct.swaps.load(Ordering::SeqCst), 3);
    assert_eq!(in_flight(&s.wallet).await, 0);
    assert_eq!(s.seller.spendable().await.unwrap(), 6);
}

//! Share Accounting Extension Mock Server
//!
//! A comprehensive mock server for testing the complete Share Accounting Extension
//! transparency system with demand-cli. Handles all required messages for PPLNS-JD.

use anyhow::Result;
use clap::Parser;
use demand_share_accounting_ext::ShareOk;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use ::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
use binary_sv2::{B032, B064K, Seq064K};
use codec_sv2::{HandshakeRole, StandardEitherFrame, StandardSv2Frame};
use demand_share_accounting_ext::{
    ErrorMessage, GetShares, GetSharesSuccess, GetWindow, GetWindowBusy, GetWindowSuccess, Hash256,
    NewBlockFound, NewTxs, PHash, RequestExtensions, RequestExtensionsError,
    RequestExtensionsSuccess, Share, Slice,
    parser::{ExtensionNegotiationMessages, PoolExtMessages, ShareAccountingMessages},
};
use demand_sv2_connection::noise_connection_tokio::Connection;
use noise_sv2::Responder;
use roles_logic_sv2::{common_messages_sv2::SetupConnectionSuccess, parsers::CommonMessages};
use secp256k1::{Keypair, Secp256k1, rand};

type StdFrame = StandardSv2Frame<PoolExtMessages<'static>>;
type EitherFrame = StandardEitherFrame<PoolExtMessages<'static>>;

#[derive(Parser, Debug)]
#[command(name = "share-accounting-mock-server")]
#[command(about = "Mock server for testing Share Accounting Extension")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value = "18442")]
    port: u16,

    /// Extension negotiation behavior
    #[arg(long, value_enum, default_value = "success")]
    extension_mode: ExtensionMode,

    /// Mock server behavior mode
    #[arg(long, value_enum, default_value = "honest")]
    server_mode: ServerMode,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum ExtensionMode {
    /// Always accept extension negotiation
    Success,
    /// Always reject extension negotiation
    Reject,
    /// Accept partial extensions only
    Partial,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum ServerMode {
    /// Honest pool behavior (correct data)
    Honest,
    /// Dishonest pool (incorrect payouts)
    Dishonest,
    /// Slow responses (test timeouts)
    Slow,
    /// Random errors
    Faulty,
}

#[derive(Debug, Clone)]
struct MockPoolState {
    /// Current PPLNS window
    current_window: Vec<Slice>,
    /// Current PHash entries
    phashes: Vec<PHash>,
    /// Shares for each slice (job_id -> shares)
    slice_shares: HashMap<u64, Vec<Share<'static>>>,
    /// Block height counter
    block_height: u64,
    /// Request ID counter
    request_counter: u32,
}

impl Default for MockPoolState {
    fn default() -> Self {
        Self {
            current_window: Vec::new(),
            phashes: Vec::new(),
            slice_shares: HashMap::new(),
            block_height: 850000,
            request_counter: 1,
        }
    }
}

#[derive(Debug)]
struct MockServer {
    port: u16,
    extension_mode: ExtensionMode,
    server_mode: ServerMode,
    server_keypair: Secp256k1SecretKey,
    server_public_key: Secp256k1PublicKey,
    pool_state: MockPoolState,
}

fn generate_base58_key() -> (Secp256k1SecretKey, Secp256k1PublicKey, String) {
    let secp = Secp256k1::new();
    let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
    let kp = Keypair::from_secret_key(&secp, &secret_key);

    if kp.x_only_public_key().1 == secp256k1::Parity::Even {
        let x_only_pub_key = kp.x_only_public_key().0;
        let base58_key = bs58::encode(x_only_pub_key.serialize()).into_string();

        info!("Generated server key: {}", base58_key);

        (
            Secp256k1SecretKey(kp.secret_key()),
            Secp256k1PublicKey(x_only_pub_key),
            base58_key,
        )
    } else {
        generate_base58_key()
    }
}

impl MockServer {
    fn new(port: u16, extension_mode: ExtensionMode, server_mode: ServerMode) -> Result<Self> {
        let (server_keypair, server_public_key, _) = generate_base58_key();
        let mut pool_state = MockPoolState::default();

        // Initialize with some mock data
        Self::initialize_mock_data(&mut pool_state);

        Ok(Self {
            port,
            extension_mode,
            server_mode,
            server_keypair,
            server_public_key,
            pool_state,
        })
    }

    fn initialize_mock_data(state: &mut MockPoolState) {
        // Create mock PPLNS window with 3 slices
        for i in 0..3 {
            let job_id = 1000 + i;
            let slice = Self::create_mock_slice(job_id, i as u32);
            let shares = Self::create_mock_shares_for_slice(&slice, 5);

            state.current_window.push(slice);
            state.slice_shares.insert(job_id, shares);
        }

        // Create mock PHash entries
        state.phashes = vec![
            PHash {
                phash: Self::random_hash256(),
                index_start: 0,
            },
            PHash {
                phash: Self::random_hash256(),
                index_start: 1,
            },
        ];
    }

    fn create_mock_slice(job_id: u64, index: u32) -> Slice {
        let number_of_shares = 5;
        let difficulty = 1000000 + (index * 100000) as u64;
        let fees = 50000 + (index * 10000) as u64;

        // Generate a mock merkle root
        let root = Self::random_hash256();

        Slice {
            job_id,
            number_of_shares,
            difficulty,
            fees,
            root,
        }
    }

    fn create_mock_shares_for_slice(slice: &Slice, count: u32) -> Vec<Share<'static>> {
        let mut shares = Vec::new();

        for i in 0..count {
            let share = Share {
                nonce: rand::random::<u32>(),
                ntime: Self::current_timestamp(),
                version: 0x20000000,
                extranonce: Self::random_b032(),
                job_id: slice.job_id,
                reference_job_id: slice.job_id,
                share_index: i,
                merkle_path: Self::generate_mock_merkle_path(),
            };
            shares.push(share);
        }

        shares
    }

    fn random_hash256() -> Hash256 {
        let random_bytes: [u8; 32] = rand::random();
        Hash256::from(random_bytes)
    }

    fn random_b032() -> B032<'static> {
        let random_bytes: [u8; 32] = rand::random();
        random_bytes.to_vec().try_into().unwrap()
    }

    fn generate_mock_merkle_path() -> B064K<'static> {
        // Generate a mock merkle path (3 levels = 96 bytes)
        let mut path = Vec::new();
        for _ in 0..3 {
            let hash: [u8; 32] = rand::random();
            path.extend_from_slice(&hash);
        }
        path.try_into().unwrap()
    }

    fn current_timestamp() -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32
    }

    async fn start(&self) -> Result<()> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let listener = TcpListener::bind(addr).await?;

        info!("Share Accounting Mock Server listening on {}", addr);
        info!("Extension mode: {:?}", self.extension_mode);
        info!("Server mode: {:?}", self.server_mode);

        while let Ok((stream, peer_addr)) = listener.accept().await {
            info!("📞 New connection from {}", peer_addr);

            let handler = ConnectionHandler {
                extension_mode: self.extension_mode.clone(),
                server_mode: self.server_mode.clone(),
                server_keypair: self.server_keypair.clone(),
                server_public_key: self.server_public_key.clone(),
                pool_state: self.pool_state.clone(),
            };

            tokio::spawn(async move {
                if let Err(e) = handler.handle_connection(stream).await {
                    error!("Connection error: {}", e);
                } else {
                    info!("Connection completed successfully");
                }
            });
        }

        Ok(())
    }
}

struct ConnectionHandler {
    extension_mode: ExtensionMode,
    server_mode: ServerMode,
    server_keypair: Secp256k1SecretKey,
    server_public_key: Secp256k1PublicKey,
    pool_state: MockPoolState,
}

impl ConnectionHandler {
    async fn handle_connection(&self, stream: TcpStream) -> Result<()> {
        // 1. Perform noise handshake
        let cert_validity_sec = Duration::from_secs(3600);
        let responder = Responder::from_authority_kp(
            &self.server_public_key.0.serialize(),
            self.server_keypair.0.as_ref(),
            cert_validity_sec,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create responder: {:?}", e))?;

        let (mut receiver, mut sender, _, _) =
            Connection::new(stream, HandshakeRole::Responder(responder))
                .await
                .map_err(|e| anyhow::anyhow!("Noise handshake failed: {:?}", e))?;

        info!("Noise handshake completed");

        // 2. Handle SetupConnection
        self.handle_setup_connection(&mut receiver, &mut sender)
            .await?;

        // 3. Handle Extension Negotiation
        if matches!(
            self.extension_mode,
            ExtensionMode::Success | ExtensionMode::Partial
        ) {
            self.handle_extension_negotiation(&mut receiver, &mut sender)
                .await?;

            // 4. Handle Share Accounting Messages
            self.handle_share_accounting_loop(&mut receiver, &mut sender)
                .await?;
        }

        info!("Mock server session completed");
        Ok(())
    }

    async fn handle_setup_connection(
        &self,
        receiver: &mut tokio::sync::mpsc::Receiver<EitherFrame>,
        sender: &mut tokio::sync::mpsc::Sender<EitherFrame>,
    ) -> Result<()> {
        info!("Waiting for SetupConnection...");

        let frame = receiver
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Connection closed"))?;

        let mut std_frame: StdFrame = frame
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to convert frame: {:?}", e))?;

        let header = std_frame
            .get_header()
            .ok_or_else(|| anyhow::anyhow!("Missing header"))?;

        debug!("Received message type: {}", header.msg_type());

        if std_frame.payload().len() > 0 {
            info!("Received SetupConnection message");

            // Apply server mode delays
            if matches!(self.server_mode, ServerMode::Slow) {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }

            let setup_success = SetupConnectionSuccess {
                used_version: 2,
                flags: 0,
            };

            let response_msg =
                PoolExtMessages::Common(CommonMessages::SetupConnectionSuccess(setup_success));
            let response_frame: StdFrame = response_msg
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to create response frame: {:?}", e))?;
            let either_frame: EitherFrame = response_frame.into();

            sender
                .send(either_frame)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to send response: {:?}", e))?;
            info!("Sent SetupConnectionSuccess");
        } else {
            return Err(anyhow::anyhow!("Invalid SetupConnection message"));
        }

        Ok(())
    }

    async fn handle_extension_negotiation(
        &self,
        receiver: &mut tokio::sync::mpsc::Receiver<EitherFrame>,
        sender: &mut tokio::sync::mpsc::Sender<EitherFrame>,
    ) -> Result<()> {
        info!("⏳ Waiting for RequestExtensions...");

        let frame = receiver
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Connection closed during extension negotiation"))?;

        let mut std_frame: StdFrame = frame
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to convert frame: {:?}", e))?;
        let mut payload = std_frame.payload().to_vec();

        if payload.len() > 0 {
            let request_extensions: RequestExtensions = binary_sv2::from_bytes(&mut payload)
                .map_err(|e| anyhow::anyhow!("Failed to parse RequestExtensions: {:?}", e))?;

            info!(
                "Received RequestExtensions: request_id={}, extensions={:?}",
                request_extensions.request_id,
                request_extensions.requested_extensions.clone().into_inner()
            );

            let response = self.generate_extension_response(request_extensions)?;
            let response_msg = PoolExtMessages::ExtensionNegotiationMessages(response);
            let response_frame: StdFrame = response_msg
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to create response frame: {:?}", e))?;
            let either_frame: EitherFrame = response_frame.into();

            sender
                .send(either_frame)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to send response: {:?}", e))?;
            info!("Sent extension negotiation response");
        }

        Ok(())
    }

    async fn handle_share_accounting_loop(
        &self,
        receiver: &mut tokio::sync::mpsc::Receiver<EitherFrame>,
        sender: &mut tokio::sync::mpsc::Sender<EitherFrame>,
    ) -> Result<()> {
        info!("🔄 Starting Share Accounting message loop...");

        // Send initial NewBlockFound to simulate a new block
        self.send_new_block_found(sender).await?;

        loop {
            tokio::select! {
                // Handle incoming messages
                frame_opt = receiver.recv() => {
                    match frame_opt {
                        Some(frame) => {
                            if let Err(e) = self.handle_share_accounting_message(frame, sender).await {
                                error!("Error handling Share Accounting message: {}", e);
                                break;
                            }
                        }
                        None => {
                            info!("Connection closed by client");
                            break;
                        }
                    }
                }
                // Simulate periodic events
                _ = tokio::time::sleep(Duration::from_secs(10)) => {
                    if matches!(self.server_mode, ServerMode::Honest) {
                        // Simulate new transactions
                        for job_id in 1001..=1005 {  // 5 job IDs: 1001, 1002, 1003, 1004, 1005
                            for share_index in 0..50 {  // 1000 shares per job_id
                                if let Err(e) = self.send_share_ok(sender, job_id, share_index).await {
                                    error!("Error sending ShareOk for job_id: {}, share_index: {}: {}", job_id, share_index, e);
                                    break; // Stop on first error to avoid spam
                                }

                                // Small delay to avoid overwhelming the connection
                                if share_index % 100 == 0 {
                                    tokio::time::sleep(Duration::from_millis(10)).await;
                                }
                            }
                            // info!("✅ Sent GetSharesSuccess");
                            // info!("✅ Sent 1000 ShareOk messages for job_id: {}", job_id);
                        }

                    }
                    if let Err(e) = self.send_new_block_found(sender).await {
                        error!("Error sending new block found: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_share_accounting_message(
        &self,
        frame: EitherFrame,
        sender: &mut tokio::sync::mpsc::Sender<EitherFrame>,
    ) -> Result<()> {
        let mut std_frame: StdFrame = frame
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to convert frame: {:?}", e))?;
        let header = std_frame
            .get_header()
            .ok_or_else(|| anyhow::anyhow!("Missing header"))?;
        let mut payload = std_frame.payload().to_vec();

        debug!(
            "Received Share Accounting message type: {}",
            header.msg_type()
        );

        // Apply server mode behavior
        match self.server_mode {
            ServerMode::Slow => tokio::time::sleep(Duration::from_millis(500)).await,
            ServerMode::Faulty => {
                if rand::random::<f32>() < 0.1 {
                    return self.send_error_message(sender, "Random server error").await;
                }
            }
            _ => {}
        }

        match header.msg_type() {
            // GetWindow message
            0x30 => {
                let get_window: GetWindow<'_> = binary_sv2::from_bytes(&mut payload)
                    .map_err(|e| anyhow::anyhow!("Failed to parse GetWindow: {:?}", e))?;
                self.handle_get_window(get_window, sender).await?;
            }
            // GetShares message
            0x32 => {
                let get_shares: GetShares<'_> = binary_sv2::from_bytes(&mut payload)
                    .map_err(|e| anyhow::anyhow!("Failed to parse GetShares: {:?}", e))?;
                self.handle_get_shares(sender).await?;
            }
            _ => {
                warn!(
                    "Unknown Share Accounting message type: {}",
                    header.msg_type()
                );
            }
        }

        Ok(())
    }

    async fn handle_get_window(
        &self,
        _request: GetWindow<'_>,
        sender: &mut tokio::sync::mpsc::Sender<EitherFrame>,
    ) -> Result<()> {
        info!("Handling GetWindow request");

        // Simulate server being busy occasionally
        if matches!(self.server_mode, ServerMode::Faulty) && rand::random::<f32>() < 0.2 {
            return self.send_window_busy(sender).await;
        }

        let slices: Seq064K<Slice> = self
            .pool_state
            .current_window
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert slices to Seq064K"))?;
        let phashes: Seq064K<PHash> = self
            .pool_state
            .phashes
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert phashes to Seq064K"))?;

        let window_success = GetWindowSuccess { slices, phashes };

        let response_msg = PoolExtMessages::ShareAccountingMessages(
            ShareAccountingMessages::GetWindowSuccess(window_success),
        );
        let response_frame: StdFrame = response_msg
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to create response frame: {:?}", e))?;
        let either_frame: EitherFrame = response_frame.into();

        sender
            .send(either_frame)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send response: {:?}", e))?;
        info!("Sent GetWindowSuccess");

        Ok(())
    }

    async fn handle_get_shares(
        &self,
        sender: &mut tokio::sync::mpsc::Sender<EitherFrame>,
    ) -> Result<()> {
        info!("Handling GetShares request");

        let shares = self
            .pool_state
            .slice_shares
            .get(&1000) // Use first job_id for demo
            .cloned()
            .unwrap_or_default();

        // Apply dishonest behavior if configured
        let shares = if matches!(self.server_mode, ServerMode::Dishonest) {
            self.corrupt_shares(shares)
        } else {
            shares
        };

        let shares_seq: Seq064K<Share> = shares
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert shares to Seq064K"))?;

        let shares_success = GetSharesSuccess { shares: shares_seq };

        let response_msg = PoolExtMessages::ShareAccountingMessages(
            ShareAccountingMessages::GetSharesSuccess(shares_success),
        );
        let response_frame: StdFrame = response_msg
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to create response frame: {:?}", e))?;
        let either_frame: EitherFrame = response_frame.into();

        sender
            .send(either_frame)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send response: {:?}", e))?;
        info!("Sent GetSharesSuccess");

        Ok(())
    }

    async fn send_window_busy(
        &self,
        sender: &mut tokio::sync::mpsc::Sender<EitherFrame>,
    ) -> Result<()> {
        let busy_msg = GetWindowBusy {
            retry_in_seconds: 30,
        };

        let response_msg = PoolExtMessages::ShareAccountingMessages(
            ShareAccountingMessages::GetWindowBusy(busy_msg),
        );
        let response_frame: StdFrame = response_msg
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to create response frame: {:?}", e))?;
        let either_frame: EitherFrame = response_frame.into();

        sender
            .send(either_frame)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send response: {:?}", e))?;
        info!("Sent GetWindowBusy");

        Ok(())
    }

    async fn send_new_block_found(
        &self,
        sender: &mut tokio::sync::mpsc::Sender<EitherFrame>,
    ) -> Result<()> {
        // Create mock hash as B032
        let block_found = NewBlockFound {
            block_hash: {
                let random_bytes: [u8; 32] = rand::random();
                random_bytes.into()
            },
        };

        let msg = PoolExtMessages::ShareAccountingMessages(ShareAccountingMessages::NewBlockFound(
            block_found,
        ));
        let frame: StdFrame = msg
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to create frame: {:?}", e))?;
        let either_frame: EitherFrame = frame.into();

        sender
            .send(either_frame)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send response: {:?}", e))?;
        info!(
            "Sent NewBlockFound for block {}",
            self.pool_state.block_height
        );

        Ok(())
    }

    async fn send_auto_shares_success(
        &self,
        sender: &mut tokio::sync::mpsc::Sender<EitherFrame>,
    ) -> Result<()> {
        info!("📦 Auto-sending GetSharesSuccess");

        // Create mock shares data - use smaller shares
        let mut shares_vec = Vec::new();
        for i in 0..3 {
            // Create proper extranonce
            let mut extranonce_data = Vec::new();
            for _ in 0..32 {
                extranonce_data.push(rand::random::<u8>());
            }
            let extranonce: binary_sv2::B032<'static> = extranonce_data
                .try_into()
                .map_err(|_| anyhow::anyhow!("Failed to convert extranonce to B032"))?;

            // Create proper merkle path
            let mut merkle_path_data = Vec::new();
            for _ in 0..96 {
                // 3 levels * 32 bytes each
                merkle_path_data.push(rand::random::<u8>());
            }
            let merkle_path: binary_sv2::B064K<'static> = merkle_path_data
                .try_into()
                .map_err(|_| anyhow::anyhow!("Failed to convert merkle_path to B064K"))?;

            let share = Share {
                nonce: rand::random::<u32>(),
                ntime: rand::random::<u32>(),
                version: 0x20000000,
                extranonce,
                job_id: 1000,
                reference_job_id: 1000,
                share_index: i,
                merkle_path,
            };
            shares_vec.push(share);
        }

        let shares: binary_sv2::Seq064K<Share> = shares_vec
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert shares to Seq064K"))?;

        let shares_success = GetSharesSuccess { shares };

        let msg = PoolExtMessages::ShareAccountingMessages(
            ShareAccountingMessages::GetSharesSuccess(shares_success),
        );
        let frame: StdFrame = msg
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to create frame: {:?}", e))?;
        let either_frame: EitherFrame = frame.into();

        sender
            .send(either_frame)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send response: {:?}", e))?;
        info!("Sent GetSharesSuccess");

        Ok(())
    }

    // Replace the entire send_new_txs function around line 658:
    async fn send_new_txs(
        &self,
        sender: &mut tokio::sync::mpsc::Sender<EitherFrame>,
    ) -> Result<()> {
        // Create mock transaction data - use smaller transactions
        let mut transactions_vec = Vec::new();
        for _ in 0..3 {
            let mut tx_data = Vec::new();
            for _ in 0..100 {
                // Create 100-byte transactions instead
                tx_data.push(rand::random::<u8>());
            }
            let tx_b016m: binary_sv2::B016M<'static> = tx_data
                .try_into()
                .map_err(|_| anyhow::anyhow!("Failed to convert tx to B016M"))?;
            transactions_vec.push(tx_b016m);
        }

        let transactions: binary_sv2::Seq064K<binary_sv2::B016M> = transactions_vec
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert transactions to Seq064K"))?;

        let new_txs = NewTxs { transactions };

        let msg =
            PoolExtMessages::ShareAccountingMessages(ShareAccountingMessages::NewTxs(new_txs));
        let frame: StdFrame = msg
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to create frame: {:?}", e))?;
        let either_frame: EitherFrame = frame.into();

        sender
            .send(either_frame)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send response: {:?}", e))?;
        info!("Sent NewTxs");

        Ok(())
    }

    async fn send_share_ok(
        &self,
        sender: &mut tokio::sync::mpsc::Sender<EitherFrame>,
        ref_job_id: u64,
        share_index: u32,
    ) -> Result<()> {
        let share_ok = ShareOk {
            ref_job_id,
            share_index,
        };

        let msg =
            PoolExtMessages::ShareAccountingMessages(ShareAccountingMessages::ShareOk(share_ok));
        let frame: StdFrame = msg
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to create frame: {:?}", e))?;
        let either_frame: EitherFrame = frame.into();

        sender
            .send(either_frame)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send response: {:?}", e))?;

        // info!(
        //     "✅ Sent ShareOk for job_id: {}, share_index: {}",
        //     ref_job_id, share_index
        // );
        Ok(())
    }

    async fn send_error_message(
        &self,
        sender: &mut tokio::sync::mpsc::Sender<EitherFrame>,
        error_text: &str,
    ) -> Result<()> {
        let message: binary_sv2::Str0255<'static> = error_text
            .to_string()
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to convert error message: {:?}", e))?;

        let error_msg = ErrorMessage { message };

        let msg = PoolExtMessages::ShareAccountingMessages(ShareAccountingMessages::ErrorMessage(
            error_msg,
        ));
        let frame: StdFrame = msg
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to create frame: {:?}", e))?;
        let either_frame: EitherFrame = frame.into();

        sender
            .send(either_frame)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send response: {:?}", e))?;
        error!("Sent ErrorMessage: {}", error_text);

        Ok(())
    }

    fn corrupt_shares(&self, mut shares: Vec<Share<'static>>) -> Vec<Share<'static>> {
        // Simulate dishonest pool behavior by corrupting share data
        for share in &mut shares {
            if rand::random::<f32>() < 0.3 {
                // Corrupt merkle path
                share.merkle_path = MockServer::generate_mock_merkle_path();
            }
            if rand::random::<f32>() < 0.2 {
                // Corrupt difficulty by changing nonce
                share.nonce = rand::random::<u32>();
            }
        }
        shares
    }

    fn generate_extension_response(
        &self,
        request: RequestExtensions,
    ) -> Result<ExtensionNegotiationMessages<'static>> {
        let requested_extensions = request.requested_extensions.into_inner().to_vec();
        const SHARE_ACCOUNTING_EXT: u16 = 32;

        match self.extension_mode {
            ExtensionMode::Success => {
                info!("Extension negotiation: SUCCESS mode - accepting all extensions");
                let supported_extensions: Seq064K<u16> = requested_extensions
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Failed to convert to Seq064K"))?;
                Ok(ExtensionNegotiationMessages::RequestExtensionsSuccess(
                    RequestExtensionsSuccess {
                        request_id: request.request_id,
                        supported_extensions,
                    },
                ))
            }

            ExtensionMode::Reject => {
                info!("Extension negotiation: REJECT mode - rejecting all extensions");
                let unsupported_extensions: Seq064K<u16> = requested_extensions
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Failed to convert to Seq064K"))?;
                let empty_requested: Seq064K<u16> = Vec::new()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Failed to convert empty vec to Seq064K"))?;
                Ok(ExtensionNegotiationMessages::RequestExtensionsError(
                    RequestExtensionsError {
                        request_id: request.request_id,
                        unsupported_extensions,
                        requested_extensions: empty_requested,
                    },
                ))
            }

            ExtensionMode::Partial => {
                info!("Extension negotiation: PARTIAL mode - accepting only extension 32");
                if requested_extensions.contains(&SHARE_ACCOUNTING_EXT) {
                    let supported_extensions: Seq064K<u16> = vec![SHARE_ACCOUNTING_EXT]
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Failed to convert to Seq064K"))?;
                    Ok(ExtensionNegotiationMessages::RequestExtensionsSuccess(
                        RequestExtensionsSuccess {
                            request_id: request.request_id,
                            supported_extensions,
                        },
                    ))
                } else {
                    let unsupported_extensions: Seq064K<u16> = requested_extensions
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Failed to convert to Seq064K"))?;
                    let empty_requested: Seq064K<u16> = Vec::new()
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Failed to convert empty vec to Seq064K"))?;
                    Ok(ExtensionNegotiationMessages::RequestExtensionsError(
                        RequestExtensionsError {
                            request_id: request.request_id,
                            unsupported_extensions,
                            requested_extensions: empty_requested,
                        },
                    ))
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let filter = if args.verbose {
        tracing_subscriber::filter::LevelFilter::DEBUG
    } else {
        tracing_subscriber::filter::LevelFilter::INFO
    };

    tracing_subscriber::fmt().with_max_level(filter).init();

    info!("Starting Share Accounting Extension Mock Server");
    info!("Extension mode: {:?}", args.extension_mode);
    info!("Server mode: {:?}", args.server_mode);

    let server = MockServer::new(args.port, args.extension_mode, args.server_mode)?;
    server.start().await?;

    Ok(())
}

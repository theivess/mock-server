//! Share Accounting Extension Mock Server
//!
//! A simple mock server for testing extension negotiation with demand-cli.
//! Handles SetupConnection and RequestExtensions messages.

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

use ::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
use binary_sv2::Seq064K;
use codec_sv2::{HandshakeRole, StandardEitherFrame, StandardSv2Frame};
use demand_share_accounting_ext::{
    RequestExtensions, RequestExtensionsError, RequestExtensionsSuccess,
    parser::{ExtensionNegotiationMessages, PoolExtMessages},
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

#[derive(Debug)]
struct MockServer {
    port: u16,
    extension_mode: ExtensionMode,
    server_keypair: Secp256k1SecretKey,
    server_public_key: Secp256k1PublicKey,
}

fn generate_key() -> (Secp256k1SecretKey, Secp256k1PublicKey) {
    let secp = Secp256k1::new();
    let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
    let kp = Keypair::from_secret_key(&secp, &secret_key);
    if kp.x_only_public_key().1 == secp256k1::Parity::Even {
        (
            Secp256k1SecretKey(kp.secret_key()),
            Secp256k1PublicKey(kp.x_only_public_key().0),
        )
    } else {
        generate_key()
    }
}

impl MockServer {
    fn new(port: u16, extension_mode: ExtensionMode) -> Result<Self> {
        let (server_keypair, server_public_key) = generate_key();

        Ok(Self {
            port,
            extension_mode,
            server_keypair,
            server_public_key,
        })
    }

    async fn start(&self) -> Result<()> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let listener = TcpListener::bind(addr).await?;
        let secp = Secp256k1::new();

        info!("Mock server listening on {}", addr);
        info!("Extension mode: {:?}", self.extension_mode);
        info!(
            "Server public key: {:?}",
            self.server_keypair.0.public_key(&secp)
        );

        while let Ok((stream, peer_addr)) = listener.accept().await {
            info!("📞 New connection from {}", peer_addr);

            let handler = ConnectionHandler {
                extension_mode: self.extension_mode.clone(),
                server_keypair: self.server_keypair.clone(),
                server_public_key: self.server_public_key.clone(),
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
    server_keypair: Secp256k1SecretKey,
    server_public_key: Secp256k1PublicKey,
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
        self.handle_extension_negotiation(&mut receiver, &mut sender)
            .await?;

        info!("Mock server session completed");
        Ok(())
    }

    async fn handle_setup_connection(
        &self,
        receiver: &mut tokio::sync::mpsc::Receiver<EitherFrame>,
        sender: &mut tokio::sync::mpsc::Sender<EitherFrame>,
    ) -> Result<()> {
        info!("Waiting for SetupConnection...");

        // Receive SetupConnection
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

        // Check if we have a payload (SetupConnection should have one)
        let payload = std_frame.payload();
        if payload.len() > 0 {
            info!("Received SetupConnection message");

            // Send SetupConnectionSuccess
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

        // Receive RequestExtensions
        let frame = receiver
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Connection closed during extension negotiation"))?;

        let mut std_frame: StdFrame = frame
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to convert frame: {:?}", e))?;

        let header = std_frame
            .get_header()
            .ok_or_else(|| anyhow::anyhow!("Missing header"))?;

        debug!("Received extension message type: {}", header.msg_type());

        let mut payload = std_frame.payload().to_vec();
        if payload.len() > 0 {
            // Parse RequestExtensions
            let request_extensions: RequestExtensions = binary_sv2::from_bytes(&mut payload)
                .map_err(|e| anyhow::anyhow!("Failed to parse RequestExtensions: {:?}", e))?;

            info!(
                "Received RequestExtensions: request_id={}, extensions={:?}",
                request_extensions.request_id,
                request_extensions.requested_extensions.clone().into_inner()
            );

            // Generate response based on mode
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
        } else {
            return Err(anyhow::anyhow!("Invalid RequestExtensions message"));
        }

        Ok(())
    }

    fn generate_extension_response(
        &self,
        request: RequestExtensions,
    ) -> Result<ExtensionNegotiationMessages<'static>> {
        let requested_extensions = request.requested_extensions.into_inner().to_vec();

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
                info!("⚠️  Extension negotiation: PARTIAL mode - accepting only extension 32");

                const SHARE_ACCOUNTING_EXT: u16 = 32;

                if requested_extensions.contains(&SHARE_ACCOUNTING_EXT) {
                    // Accept only the share accounting extension
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
                    // Reject all if share accounting not requested
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

    let server = MockServer::new(args.port, args.extension_mode)?;
    server.start().await?;

    Ok(())
}

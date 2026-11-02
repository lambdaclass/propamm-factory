//! The signer process: obtains its keys, opens its listener, and signs what its policy
//! allows for as long as it runs.

use std::{path::PathBuf, sync::Arc};

use clap::Parser;
use eyre::{Result, WrapErr};
use quote_signer::{
    config::{Config, KeySource},
    keys::{KeyFile, KeyRelease},
    reference::{Book, Poller},
    serve::{Listener, Signer, serve},
};

/// A separate signing process for a quote updater.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// The config file.
    #[arg(long, env = "QUOTE_SIGNER_CONFIG")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
    let args = Args::parse();
    let text = std::fs::read_to_string(&args.config)
        .wrap_err_with(|| format!("reading {}", args.config.display()))?;
    let config = Config::parse(&text).wrap_err_with(|| args.config.display().to_string())?;

    #[cfg(not(target_os = "linux"))]
    if let Some(tunnel) = config.forward.first() {
        eyre::bail!(
            "[[forward]] {} needs vsock, which exists on Linux only",
            tunnel.listen
        );
    }
    #[cfg(target_os = "linux")]
    for tunnel in &config.forward {
        let (listen, cid, port) = (tunnel.listen, tunnel.cid, tunnel.port);
        tokio::spawn(async move {
            if let Err(err) = quote_signer::forward::run(listen, cid, port).await {
                tracing::error!("tunnel {listen}: {err:#}");
            }
        });
    }

    let keys = match &config.keys {
        KeySource::File(path) => KeyFile { path: path.clone() }.release().await?,
        #[cfg(feature = "nitro")]
        KeySource::Nitro(settings) => {
            quote_signer::nitro::NitroRelease {
                settings: settings.clone(),
            }
            .release()
            .await?
        }
        #[cfg(not(feature = "nitro"))]
        KeySource::Nitro(_) => eyre::bail!("[keys] nitro needs a build with the `nitro` feature"),
    };

    let book = Arc::new(Book::default());
    let signer = Arc::new(Signer::new(keys, config.policy, Arc::clone(&book))?);
    for address in signer.addresses() {
        tracing::info!("signing for {address:#x}");
    }
    let symbols = signer.reference_symbols();
    if !symbols.is_empty() {
        tracing::info!(
            "reference prices for {} from {} every {:?}",
            symbols.join(", "),
            config.reference.base_url,
            config.reference.every
        );
        let poller = Poller::new(
            config.reference.base_url,
            symbols,
            config.reference.every,
            Arc::clone(&book),
        )?;
        tokio::spawn(poller.run());
    }

    let socket = match &config.listen {
        Listener::Unix(path) => Some(path.clone()),
        Listener::Vsock(_) => None,
    };
    let outcome = tokio::select! {
        outcome = serve(config.listen, signer) => outcome,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("stopping");
            Ok(())
        }
    };
    if let Some(path) = socket {
        let _ = std::fs::remove_file(path);
    }
    outcome
}

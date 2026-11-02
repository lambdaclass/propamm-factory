//! A separate signing process for a quote updater, and the client the updater embeds to
//! use it.
//!
//! The updater builds each update's transaction as it always has; instead of holding the
//! key, it sends the unsigned fields to this process and gets the signature back. The
//! process holds the keys, and before signing anything it decodes the transaction and
//! judges it against a policy: the registry it may call, the lanes each key may quote, and
//! how far a published mid may sit from a reference price the process reads for itself.
//! So a host that can reach the signer can get updates signed, and nothing else.
//!
//! How the keys reach the process is the one part that depends on where it runs:
//! [`keys::KeyFile`] on a plain host, and the Nitro Enclaves release (`nitro`, behind its
//! feature) where the keys are stored as KMS ciphertext that only the attested enclave can
//! have decrypted.
#![warn(missing_docs)]

pub mod client;
pub mod config;
#[cfg(target_os = "linux")]
pub mod forward;
pub mod keys;
#[cfg(feature = "nitro")]
pub mod nitro;
pub mod policy;
pub mod protocol;
pub mod reference;
pub mod serve;
pub mod signing;
pub mod spec;

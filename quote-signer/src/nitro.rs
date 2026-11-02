//! The AWS Nitro Enclaves key release. The keys are stored as KMS ciphertext, and the KMS
//! key's policy allows `Decrypt` only to a request carrying an attestation document whose
//! measurements match this program's enclave image. So the sequence at boot is: a helper
//! on the host connects over vsock and hands in the ciphertexts and a set of temporary
//! credentials; the enclave generates a fresh RSA key, asks the Nitro Security Module for
//! an attestation document that includes its public half, and calls KMS `Decrypt` with the
//! document; KMS checks the measurements, decrypts, and returns the plaintext encrypted to
//! that public key as a CMS envelope, which only this process can open. The plaintext key
//! then exists in this process's memory and nowhere else.
//!
//! An enclave has no network: KMS is reached through a loopback port a `[[forward]]`
//! tunnels to a proxy on the host (`kms_endpoint` in the config).

use aws_nitro_enclaves_nsm_api::{
    api::{Request as NsmRequest, Response as NsmResponse},
    driver,
};
use aws_sdk_kms::{
    Client,
    config::{BehaviorVersion, Credentials, Region},
    primitives::Blob,
    types::{KeyEncryptionMechanism, RecipientInfo},
};
use base64::Engine;
use eyre::{Result, WrapErr, bail, ensure, eyre};
use rsa::{Oaep, RsaPrivateKey, pkcs8::EncodePublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{
    config::NitroSettings,
    keys::KeyRelease,
    protocol::{read_frame, write_frame},
    signing::SigningKey,
};

/// What the host's boot helper sends: credentials that may call `Decrypt` on the KMS key,
/// and the ciphertexts.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Boot {
    /// The access key id of the credentials.
    pub access_key_id: String,
    /// Their secret.
    pub secret_access_key: String,
    /// Their session token, for temporary credentials (an instance role's).
    #[serde(default)]
    pub session_token: Option<String>,
    /// Each key as KMS `Encrypt` returned it, base64.
    pub ciphertexts: Vec<String>,
}

impl std::fmt::Debug for Boot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Boot({} ciphertexts)", self.ciphertexts.len())
    }
}

/// What the enclave answers the boot helper, so the host's log says what happened inside.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BootReply {
    /// Every key was released; these are their addresses.
    Loaded {
        /// The addresses, sorted.
        addresses: Vec<ethrex_common::Address>,
    },
    /// The release failed; the enclave exits.
    Failed {
        /// Why.
        message: String,
    },
}

/// The Nitro key release.
#[derive(Clone, Debug)]
pub struct NitroRelease {
    /// Its settings.
    pub settings: NitroSettings,
}

impl KeyRelease for NitroRelease {
    async fn release(&self) -> Result<Vec<SigningKey>> {
        let mut stream = accept_boot(self.settings.boot_port).await?;
        let boot: Boot = read_frame(&mut stream)
            .await?
            .ok_or_else(|| eyre!("the boot helper closed the connection before sending"))?;
        let outcome = self.decrypt_all(boot).await;
        let reply = match &outcome {
            Ok(keys) => BootReply::Loaded {
                addresses: {
                    let mut addresses: Vec<_> = keys.iter().map(SigningKey::address).collect();
                    addresses.sort();
                    addresses
                },
            },
            Err(err) => BootReply::Failed {
                message: format!("{err:#}"),
            },
        };
        write_frame(&mut stream, &reply).await?;
        outcome
    }
}

impl NitroRelease {
    async fn decrypt_all(&self, boot: Boot) -> Result<Vec<SigningKey>> {
        ensure!(
            !boot.ciphertexts.is_empty(),
            "the boot message carries no ciphertexts"
        );
        let rsa = RsaPrivateKey::new(&mut rand::thread_rng(), 2048)
            .wrap_err("generating the recipient key")?;
        let public_der = rsa
            .to_public_key()
            .to_public_key_der()
            .wrap_err("encoding the recipient public key")?
            .into_vec();
        let document = attestation(public_der)?;

        let credentials = Credentials::new(
            boot.access_key_id,
            boot.secret_access_key,
            boot.session_token,
            None,
            "boot-helper",
        );
        let mut config = aws_sdk_kms::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(self.settings.region.clone()))
            .credentials_provider(credentials);
        if let Some(endpoint) = &self.settings.kms_endpoint {
            config = config.endpoint_url(endpoint);
        }
        let client = Client::from_conf(config.build());

        let mut keys = Vec::with_capacity(boot.ciphertexts.len());
        for (index, ciphertext) in boot.ciphertexts.iter().enumerate() {
            let blob = base64::engine::general_purpose::STANDARD
                .decode(ciphertext.trim())
                .wrap_err_with(|| format!("ciphertext #{} is not base64", index + 1))?;
            let output = client
                .decrypt()
                .ciphertext_blob(Blob::new(blob))
                .recipient(
                    RecipientInfo::builder()
                        .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
                        .attestation_document(Blob::new(document.clone()))
                        .build(),
                )
                .send()
                .await
                .map_err(|err| eyre!("KMS Decrypt of ciphertext #{}: {}", index + 1, err))?;
            let envelope = output
                .ciphertext_for_recipient()
                .ok_or_else(|| eyre!("KMS answered without a ciphertext for the recipient"))?;
            let plaintext = unwrap_envelope(envelope.as_ref(), &rsa)
                .wrap_err_with(|| format!("opening the envelope of ciphertext #{}", index + 1))?;
            let text = std::str::from_utf8(&plaintext)
                .map_err(|_| eyre!("ciphertext #{} does not decrypt to text", index + 1))?;
            keys.push(
                SigningKey::parse(text).wrap_err_with(|| format!("ciphertext #{}", index + 1))?,
            );
        }
        Ok(keys)
    }
}

#[cfg(target_os = "linux")]
async fn accept_boot(port: u32) -> Result<tokio_vsock::VsockStream> {
    let listener = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(
        tokio_vsock::VMADDR_CID_ANY,
        port,
    ))
    .wrap_err_with(|| format!("binding the boot port {port}"))?;
    tracing::info!("waiting for the boot helper on vsock port {port}");
    let (stream, _) = listener.accept().await?;
    Ok(stream)
}

/// Off Linux there is no vsock and no enclave; the type only has to exist for the code
/// above to compile and be tested where it can be.
#[cfg(not(target_os = "linux"))]
async fn accept_boot(port: u32) -> Result<tokio::io::DuplexStream> {
    bail!("the boot port {port} needs vsock, which exists on Linux only")
}

/// An attestation document from the Nitro Security Module carrying `public_key`.
fn attestation(public_key: Vec<u8>) -> Result<Vec<u8>> {
    let fd = driver::nsm_init();
    ensure!(
        fd >= 0,
        "no Nitro Security Module: not running inside a Nitro enclave"
    );
    let response = driver::nsm_process_request(
        fd,
        NsmRequest::Attestation {
            user_data: None,
            nonce: None,
            public_key: Some(serde_bytes::ByteBuf::from(public_key)),
        },
    );
    driver::nsm_exit(fd);
    match response {
        NsmResponse::Attestation { document } => Ok(document),
        NsmResponse::Error(code) => bail!("attestation failed: {code:?}"),
        other => bail!("unexpected answer to the attestation request: {other:?}"),
    }
}

/// Opens the CMS `EnvelopedData` KMS returns for a recipient: the content key is unwrapped
/// with RSA-OAEP (SHA-256) under `key`, and the content is AES-256-CBC under it.
pub fn unwrap_envelope(der_bytes: &[u8], key: &RsaPrivateKey) -> Result<Vec<u8>> {
    use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
    use cms::{
        content_info::ContentInfo,
        enveloped_data::{EnvelopedData, RecipientInfo},
    };
    use der::{Decode, asn1::OctetString};

    let info =
        ContentInfo::from_der(der_bytes).map_err(|err| eyre!("not a CMS envelope: {err}"))?;
    let enveloped: EnvelopedData = info
        .content
        .decode_as()
        .map_err(|err| eyre!("not EnvelopedData: {err}"))?;
    let recipient = enveloped
        .recip_infos
        .0
        .iter()
        .find_map(|info| match info {
            RecipientInfo::Ktri(ktri) => Some(ktri),
            _ => None,
        })
        .ok_or_else(|| eyre!("no key-transport recipient in the envelope"))?;
    let content_key = key
        .decrypt(Oaep::new::<Sha256>(), recipient.enc_key.as_bytes())
        .map_err(|err| eyre!("unwrapping the content key: {err}"))?;
    ensure!(content_key.len() == 32, "the content key is not AES-256");

    let encrypted = enveloped.encrypted_content;
    let iv: OctetString = encrypted
        .content_enc_alg
        .parameters
        .ok_or_else(|| eyre!("the content cipher carries no IV"))?
        .decode_as()
        .map_err(|err| eyre!("the content cipher's IV: {err}"))?;
    let content = encrypted
        .encrypted_content
        .ok_or_else(|| eyre!("the envelope carries no content"))?;
    let decryptor = cbc::Decryptor::<aes::Aes256>::new_from_slices(&content_key, iv.as_bytes())
        .map_err(|err| eyre!("content cipher: {err}"))?;
    decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(content.as_bytes())
        .map_err(|err| eyre!("decrypting the content: {err}"))
}

#[cfg(test)]
mod tests {
    use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
    use cms::{
        cert::x509::ext::pkix::SubjectKeyIdentifier,
        content_info::ContentInfo,
        enveloped_data::{
            EncryptedContentInfo, EnvelopedData, KeyTransRecipientInfo, RecipientIdentifier,
            RecipientInfo, RecipientInfos,
        },
    };
    use der::{
        Any, Encode,
        asn1::{OctetString, SetOfVec},
    };
    use rsa::RsaPublicKey;
    use spki::AlgorithmIdentifierOwned;

    use super::*;

    const ID_ENVELOPED_DATA: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");
    const ID_DATA: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
    const ID_RSAES_OAEP: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.7");
    const ID_AES_256_CBC: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");

    /// An envelope in the shape KMS returns: RSA-OAEP-SHA256 key transport, AES-256-CBC
    /// content.
    fn envelope(plaintext: &[u8], recipient: &RsaPublicKey) -> Vec<u8> {
        let content_key = [0x11u8; 32];
        let iv = [0x22u8; 16];
        let ciphertext = cbc::Encryptor::<aes::Aes256>::new(&content_key.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
        let wrapped = recipient
            .encrypt(&mut rand::thread_rng(), Oaep::new::<Sha256>(), &content_key)
            .unwrap();
        let ktri = KeyTransRecipientInfo {
            version: cms::content_info::CmsVersion::V2,
            rid: RecipientIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier(
                OctetString::new([0u8; 20]).unwrap(),
            )),
            key_enc_alg: AlgorithmIdentifierOwned {
                oid: ID_RSAES_OAEP,
                parameters: None,
            },
            enc_key: OctetString::new(wrapped).unwrap(),
        };
        let enveloped = EnvelopedData {
            version: cms::content_info::CmsVersion::V2,
            originator_info: None,
            recip_infos: RecipientInfos(
                SetOfVec::try_from(vec![RecipientInfo::Ktri(ktri)]).unwrap(),
            ),
            encrypted_content: EncryptedContentInfo {
                content_type: ID_DATA,
                content_enc_alg: AlgorithmIdentifierOwned {
                    oid: ID_AES_256_CBC,
                    parameters: Some(Any::encode_from(&OctetString::new(iv).unwrap()).unwrap()),
                },
                encrypted_content: Some(OctetString::new(ciphertext).unwrap()),
            },
            unprotected_attrs: None,
        };
        ContentInfo {
            content_type: ID_ENVELOPED_DATA,
            content: Any::encode_from(&enveloped).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    #[test]
    fn the_envelope_opens_for_its_recipient_only() {
        let recipient = RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
        let other = RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
        let der = envelope(
            b"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            &recipient.to_public_key(),
        );
        let plaintext = unwrap_envelope(&der, &recipient).unwrap();
        assert!(SigningKey::parse(std::str::from_utf8(&plaintext).unwrap()).is_ok());
        assert!(unwrap_envelope(&der, &other).is_err());
        assert!(unwrap_envelope(b"not der", &recipient).is_err());
    }

    #[test]
    fn the_boot_message_never_shows_its_credentials() {
        let boot = Boot {
            access_key_id: "AKIA".into(),
            secret_access_key: "verysecret".into(),
            session_token: None,
            ciphertexts: vec!["AAAA".into()],
        };
        let shown = format!("{boot:?}");
        assert!(
            !shown.contains("verysecret") && !shown.contains("AKIA"),
            "{shown}"
        );
    }
}

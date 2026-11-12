//! The `aws-nitro-kms` release: AWS KMS decrypts each secret only for a request carrying an
//! AWS Nitro enclave's attestation document whose measurements match its key policy, and
//! returns the plaintext encrypted to a public key inside that document, so it crosses the
//! host as ciphertext and only this process can open it.
//!
//! Per boot: a fresh RSA key pair is generated in memory; the Nitro Security Module signs an
//! attestation document carrying its public half and the image's measurements; each
//! ciphertext goes to KMS `Decrypt` with the document attached; KMS answers with a CMS
//! envelope (RSA-OAEP-SHA256 key transport, AES-256-CBC content) that the private half
//! opens. The RSA key and the credentials are dropped when the boot ends.

use aws_nitro_enclaves_nsm_api::{
    api::{Request as NsmRequest, Response as NsmResponse},
    driver,
};
use aws_sdk_kms::{
    Client,
    config::{BehaviorVersion, Region},
    primitives::Blob,
    types::{KeyEncryptionMechanism, RecipientInfo},
};
use eyre::{Result, WrapErr, bail, ensure, eyre};
use futures_util::future::BoxFuture;
use openssl::{
    cms::CmsContentInfo,
    pkey::{PKey, PKeyRef, Private},
    rsa::Rsa,
};

use super::{SecretRelease, protocol::Credentials};

/// The encryption-context key every secret is encrypted and decrypted under, its value the
/// secret's name.
pub const ENCRYPTION_CONTEXT_KEY: &str = "secret";

/// AWS KMS against this enclave's attestation. The boot message's credentials are an AWS
/// role's: `access_key_id`, `secret_access_key` and, for temporary ones, `session_token`.
pub struct AwsNitroKms {
    /// The region the KMS key lives in.
    pub region: String,
    /// The key every secret must be under, as an ARN.
    pub key_id: String,
    /// Where KMS is reached, when not its public endpoint.
    pub endpoint: Option<String>,
}

impl SecretRelease for AwsNitroKms {
    fn release<'a>(
        &'a self,
        credentials: &'a Credentials,
        secrets: &'a [(String, Vec<u8>)],
    ) -> BoxFuture<'a, Result<Vec<Vec<u8>>>> {
        Box::pin(decrypt_all(self, credentials, secrets))
    }
}

/// The plaintext of every ciphertext, in order, decrypted by KMS against this enclave's
/// attestation.
///
/// Each decrypt names the key and carries the secret's name as its encryption context
/// (`secret = <name>`), which the ciphertext was made with (`aws kms encrypt
/// --encryption-context secret=<name>`). KMS refuses anything else: a ciphertext under a
/// key the host made, and one the host relabelled to stand in for another secret.
async fn decrypt_all(
    kms: &AwsNitroKms,
    credentials: &Credentials,
    secrets: &[(String, Vec<u8>)],
) -> Result<Vec<Vec<u8>>> {
    let key = Rsa::generate(2048)
        .and_then(PKey::from_rsa)
        .wrap_err("generating the recipient key")?;
    let public_der = key
        .public_key_to_der()
        .wrap_err("encoding the recipient public key")?;
    let document = attestation(public_der)?;

    let provider = aws_sdk_kms::config::Credentials::new(
        credential(credentials, "access_key_id")?,
        credential(credentials, "secret_access_key")?,
        credentials.0.get("session_token").cloned(),
        None,
        "enclave-boot",
    );
    let mut config = aws_sdk_kms::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(kms.region.clone()))
        .credentials_provider(provider);
    if let Some(endpoint) = &kms.endpoint {
        config = config.endpoint_url(endpoint);
    }
    let client = Client::from_conf(config.build());

    let mut plaintexts = Vec::with_capacity(secrets.len());
    for (name, ciphertext) in secrets {
        let output = client
            .decrypt()
            .key_id(&kms.key_id)
            .encryption_context(ENCRYPTION_CONTEXT_KEY, name)
            .ciphertext_blob(Blob::new(ciphertext.clone()))
            .recipient(
                RecipientInfo::builder()
                    .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
                    .attestation_document(Blob::new(document.clone()))
                    .build(),
            )
            .send()
            .await
            .map_err(|err| eyre!("KMS Decrypt of secret {name}: {err}"))?;
        let envelope = output
            .ciphertext_for_recipient()
            .ok_or_else(|| eyre!("KMS answered without a ciphertext for the recipient"))?;
        plaintexts.push(
            unwrap_envelope(envelope.as_ref(), &key)
                .wrap_err_with(|| format!("opening the envelope of secret {name}"))?,
        );
    }
    Ok(plaintexts)
}

/// The credential under `name`, or why there is none.
fn credential(credentials: &Credentials, name: &str) -> Result<String> {
    credentials
        .0
        .get(name)
        .cloned()
        .ok_or_else(|| eyre!("the boot message's credentials have no {name}"))
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

/// Opens the CMS `EnvelopedData` KMS returns for a recipient (RSA-OAEP-SHA256 key transport,
/// AES-256-CBC content) with the private half of `key`.
///
/// KMS encodes the envelope in BER, with indefinite lengths and the content in pieces. A
/// DER-only parser refuses that ("indefinite length disallowed" on a live `Decrypt`), and
/// OpenSSL reads it as it is. OpenSSL takes the algorithms from the envelope itself; the
/// envelope comes from KMS over TLS.
///
/// No recipient certificate is checked, because KMS encrypts to the attestation document's
/// bare public key, which has none. Without a certificate, OpenSSL defends against a padding
/// oracle: when `key` does not unwrap the content key, it decrypts with a random one instead.
/// So the wrong `key` gives an error or, rarely, bytes that are not the plaintext.
pub fn unwrap_envelope(envelope: &[u8], key: &PKeyRef<Private>) -> Result<Vec<u8>> {
    CmsContentInfo::from_der(envelope)
        .map_err(|err| eyre!("not a CMS envelope: {err}"))?
        .decrypt_without_cert_check(key)
        .map_err(|err| eyre!("opening the envelope: {err}"))
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
        Any, Decode, Encode, Header, Reader, SliceReader, Tag,
        asn1::{OctetString, SetOfVec},
    };
    use rsa::{Oaep, RsaPublicKey, pkcs1::RsaOaepParams, pkcs8::DecodePublicKey};
    use sha2::Sha256;
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

    /// A throwaway recipient key; 1024 bits keeps the tests fast.
    fn recipient_key() -> PKey<Private> {
        PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap()
    }

    /// An envelope in the shape KMS returns: RSA-OAEP-SHA256 key transport, with its
    /// parameters written out (OpenSSL reads the hash from them; absent, OAEP means SHA-1),
    /// and AES-256-CBC content. It is built with RustCrypto so that OpenSSL is tested against
    /// an encoder other than its own.
    fn envelope(plaintext: &[u8], recipient: &PKeyRef<Private>) -> Vec<u8> {
        let recipient =
            RsaPublicKey::from_public_key_der(&recipient.public_key_to_der().unwrap()).unwrap();
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
                parameters: Some(Any::encode_from(&RsaOaepParams::new::<Sha256>()).unwrap()),
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

    /// `der` re-encoded the way KMS answers: every constructed element with an indefinite
    /// length, and every OCTET STRING longer than 8 bytes (universal, or under an implicit
    /// context tag such as the encrypted content's `[0]`) sent in 8-byte pieces.
    fn as_kms_ber(der: &[u8]) -> Vec<u8> {
        let mut reader = SliceReader::new(der).unwrap();
        let mut out = Vec::new();
        while !reader.is_finished() {
            let header = Header::decode(&mut reader).unwrap();
            let content = reader.read_slice(header.length).unwrap();
            let tag = u8::from(header.tag);
            if header.tag.is_constructed() {
                out.extend([tag, 0x80]);
                out.extend(as_kms_ber(content));
                out.extend([0, 0]);
            } else if (tag == 0x04 || tag == 0x80) && content.len() > 8 {
                out.extend([tag | 0x20, 0x80]);
                for piece in content.chunks(8) {
                    Header::new(Tag::OctetString, piece.len())
                        .unwrap()
                        .encode_to_vec(&mut out)
                        .unwrap();
                    out.extend(piece);
                }
                out.extend([0, 0]);
            } else {
                header.encode_to_vec(&mut out).unwrap();
                out.extend(content);
            }
        }
        out
    }

    #[test]
    fn the_envelope_opens_for_its_recipient_only() {
        let recipient = recipient_key();
        let der = envelope(b"a secret", &recipient);
        assert_eq!(unwrap_envelope(&der, &recipient).unwrap(), b"a secret");
        // Usually an error, but OpenSSL's padding-oracle defence can hand back random bytes
        // (see unwrap_envelope): what never comes back is the plaintext.
        let other = unwrap_envelope(&der, &recipient_key());
        assert_ne!(other.ok().as_deref(), Some(&b"a secret"[..]));
        assert!(unwrap_envelope(b"not der", &recipient).is_err());
    }

    #[test]
    fn a_kms_ber_envelope_opens_like_its_der() {
        let recipient = recipient_key();
        let der = envelope(b"a secret held by KMS", &recipient);
        let ber = as_kms_ber(&der);
        assert_ne!(ber, der, "the test envelope must exercise BER");
        // A DER-only parser refuses it: the failure seen on a live Decrypt.
        assert!(ContentInfo::from_der(&ber).is_err());
        assert_eq!(
            unwrap_envelope(&ber, &recipient).unwrap(),
            b"a secret held by KMS"
        );
        // Cut short, it is refused rather than misread.
        assert!(unwrap_envelope(&ber[..ber.len() - 2], &recipient).is_err());
    }

    #[test]
    fn attestation_outside_an_enclave_says_so() {
        let err = attestation(vec![1, 2, 3]).unwrap_err().to_string();
        assert!(err.contains("Nitro"), "{err}");
    }
}

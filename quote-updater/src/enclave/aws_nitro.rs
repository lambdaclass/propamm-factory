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
use rsa::{Oaep, RsaPrivateKey, pkcs8::EncodePublicKey};
use sha2::Sha256;

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
    let rsa = RsaPrivateKey::new(&mut rand::thread_rng(), 2048)
        .wrap_err("generating the recipient key")?;
    let public_der = rsa
        .to_public_key()
        .to_public_key_der()
        .wrap_err("encoding the recipient public key")?
        .into_vec();
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
            unwrap_envelope(envelope.as_ref(), &rsa)
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

/// Opens the CMS `EnvelopedData` KMS returns for a recipient: the content key is unwrapped
/// with RSA-OAEP (SHA-256) under `key`, and the content is AES-256-CBC under it.
///
/// KMS encodes the envelope in BER, not DER: indefinite lengths, and the content split into
/// pieces (seen on a live `Decrypt`, which `der` refuses with "indefinite length
/// disallowed"). It is rewritten as DER first ([`ber_to_der`]); a DER envelope passes
/// through unchanged.
pub fn unwrap_envelope(ber_bytes: &[u8], key: &RsaPrivateKey) -> Result<Vec<u8>> {
    use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
    use cms::{
        content_info::ContentInfo,
        enveloped_data::{EnvelopedData, RecipientInfo},
    };
    use der::{Decode, asn1::OctetString};

    let der_bytes = ber_to_der(ber_bytes).wrap_err("not a CMS envelope")?;
    let info =
        ContentInfo::from_der(&der_bytes).map_err(|err| eyre!("not a CMS envelope: {err}"))?;
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

/// How deep [`ber_to_der`] follows nested elements. A CMS envelope is under ten levels; the
/// bound only stops a hostile input from exhausting the stack.
const MAX_BER_DEPTH: usize = 32;

/// `ber` (one BER element, as KMS encodes its envelope) rewritten as DER, which `der` and
/// `cms` read: every length definite and minimal, and every string sent in pieces (a
/// constructed OCTET STRING, universal or under an implicit context tag) joined into one
/// primitive string. DER input comes back unchanged.
///
/// A context-specific constructed element is taken for a string in pieces when its encoding
/// was indefinite or had more than one part, and every part is an OCTET STRING. An explicit
/// tag around a single OCTET STRING, encoded with a definite length, is left alone. CMS
/// `EnvelopedData` has no explicit tag around an OCTET STRING, so the rule is exact for it.
pub fn ber_to_der(ber: &[u8]) -> Result<Vec<u8>> {
    let (der, rest) = ber_element(ber, 0)?;
    ensure!(rest.is_empty(), "{} bytes after the element", rest.len());
    Ok(der)
}

/// A BER header: the tag bytes, whether the element is constructed, and its length (`None`
/// for an indefinite length).
struct BerHeader {
    tag: Vec<u8>,
    constructed: bool,
    len: Option<usize>,
}

fn ber_header(input: &[u8]) -> Result<(BerHeader, &[u8])> {
    let (&first, mut rest) = input
        .split_first()
        .ok_or_else(|| eyre!("truncated: no tag"))?;
    let mut tag = vec![first];
    if first & 0x1f == 0x1f {
        // High tag number: base-128 bytes, the last one with its top bit clear.
        loop {
            let (&byte, after) = rest.split_first().ok_or_else(|| eyre!("truncated tag"))?;
            tag.push(byte);
            rest = after;
            if byte & 0x80 == 0 {
                break;
            }
            ensure!(tag.len() <= 6, "tag too long");
        }
    }
    let (&first_len, after) = rest
        .split_first()
        .ok_or_else(|| eyre!("truncated: no length"))?;
    rest = after;
    let len = match first_len {
        0x00..=0x7f => Some(usize::from(first_len)),
        0x80 => None,
        _ => {
            let count = usize::from(first_len & 0x7f);
            ensure!(count <= 4, "length of {count} bytes");
            ensure!(rest.len() >= count, "truncated length");
            let (bytes, after) = rest.split_at(count);
            rest = after;
            Some(
                bytes
                    .iter()
                    .fold(0usize, |len, &byte| (len << 8) | usize::from(byte)),
            )
        }
    };
    Ok((
        BerHeader {
            tag,
            constructed: first & 0x20 != 0,
            len,
        },
        rest,
    ))
}

/// One element of `input` as DER, and what follows it.
fn ber_element(input: &[u8], depth: usize) -> Result<(Vec<u8>, &[u8])> {
    ensure!(
        depth <= MAX_BER_DEPTH,
        "nested more than {MAX_BER_DEPTH} deep"
    );
    let (header, rest) = ber_header(input)?;
    if !header.constructed {
        let len = header
            .len
            .ok_or_else(|| eyre!("a primitive element with an indefinite length"))?;
        ensure!(rest.len() >= len, "truncated content");
        let (content, after) = rest.split_at(len);
        return Ok((der_encode(&header.tag, content), after));
    }

    let mut parts = Vec::new();
    let after = match header.len {
        Some(len) => {
            ensure!(rest.len() >= len, "truncated content");
            let (mut body, after) = rest.split_at(len);
            while !body.is_empty() {
                let (part, next) = ber_element(body, depth + 1)?;
                parts.push(part);
                body = next;
            }
            after
        }
        None => {
            let mut body = rest;
            loop {
                ensure!(body.len() >= 2, "truncated: no end-of-contents");
                if body[..2] == [0, 0] {
                    break &body[2..];
                }
                let (part, next) = ber_element(body, depth + 1)?;
                parts.push(part);
                body = next;
            }
        }
    };

    let tag = header.tag[0];
    let all_octet_strings = !parts.is_empty() && parts.iter().all(|part| part[0] == 0x04);
    let in_pieces = header.tag.len() == 1
        && all_octet_strings
        && (tag == 0x24 || (tag & 0xc0 == 0x80 && (header.len.is_none() || parts.len() > 1)));
    if in_pieces {
        let mut content = Vec::new();
        for part in &parts {
            // Already DER: a definite length.
            let (part_header, part_rest) = ber_header(part)?;
            let len = part_header.len.unwrap_or_default();
            content.extend_from_slice(&part_rest[..len]);
        }
        return Ok((der_encode(&[tag & !0x20], &content), after));
    }
    Ok((der_encode(&header.tag, &parts.concat()), after))
}

/// `tag`, the minimal definite length of `content`, then `content`.
fn der_encode(tag: &[u8], content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + 5 + content.len());
    out.extend_from_slice(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&byte| byte == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
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
        let der = envelope(b"a secret", &recipient.to_public_key());
        assert_eq!(unwrap_envelope(&der, &recipient).unwrap(), b"a secret");
        assert!(unwrap_envelope(&der, &other).is_err());
        assert!(unwrap_envelope(b"not der", &recipient).is_err());
    }

    /// `der` re-encoded the way KMS answers: every constructed element with an indefinite
    /// length, and every OCTET STRING longer than 8 bytes (universal, or under an implicit
    /// context tag such as the encrypted content's `[0]`) sent in 8-byte pieces.
    fn as_kms_ber(der: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut rest = der;
        while !rest.is_empty() {
            let (header, after) = ber_header(rest).unwrap();
            let (content, after) = after.split_at(header.len.unwrap());
            let tag = header.tag[0];
            if header.constructed {
                out.extend_from_slice(&header.tag);
                out.push(0x80);
                out.extend(as_kms_ber(content));
                out.extend([0, 0]);
            } else if (tag == 0x04 || tag == 0x80) && content.len() > 8 {
                out.extend([tag | 0x20, 0x80]);
                for piece in content.chunks(8) {
                    out.extend(der_encode(&[0x04], piece));
                }
                out.extend([0, 0]);
            } else {
                out.extend(der_encode(&header.tag, content));
            }
            rest = after;
        }
        out
    }

    #[test]
    fn a_kms_ber_envelope_opens_like_its_der() {
        let recipient = RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
        let der = envelope(b"a secret held by KMS", &recipient.to_public_key());
        let ber = as_kms_ber(&der);
        assert_ne!(ber, der, "the test envelope must exercise BER");
        // What PR #36 did, and what failed on a live Decrypt.
        assert!(<ContentInfo as der::Decode>::from_der(&ber).is_err());
        assert_eq!(ber_to_der(&ber).unwrap(), der);
        assert_eq!(
            unwrap_envelope(&ber, &recipient).unwrap(),
            b"a secret held by KMS"
        );
    }

    #[test]
    fn der_passes_through_ber_to_der_unchanged() {
        let recipient = RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
        let der = envelope(b"x", &recipient.to_public_key());
        assert_eq!(ber_to_der(&der).unwrap(), der);
    }

    #[test]
    fn broken_ber_is_refused_not_misread() {
        let recipient = RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
        let ber = as_kms_ber(&envelope(b"x", &recipient.to_public_key()));
        // Without its last end-of-contents, cut in a length, with bytes after it.
        assert!(ber_to_der(&ber[..ber.len() - 2]).is_err());
        assert!(ber_to_der(&ber[..3]).is_err());
        let mut trailing = ber.clone();
        trailing.push(0);
        assert!(ber_to_der(&trailing).is_err());
        // A primitive element cannot have an indefinite length.
        assert!(ber_to_der(&[0x04, 0x80, 0x00, 0x00]).is_err());
        // Nesting past the bound.
        let mut deep = Vec::new();
        for _ in 0..=MAX_BER_DEPTH + 1 {
            deep.extend([0x30, 0x80]);
        }
        assert!(ber_to_der(&deep).is_err());
    }

    #[test]
    fn attestation_outside_an_enclave_says_so() {
        let err = attestation(vec![1, 2, 3]).unwrap_err().to_string();
        assert!(err.contains("Nitro"), "{err}");
    }
}

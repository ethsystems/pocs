use alloy::primitives::B256;
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair,
    PKCS_ECDSA_P256_SHA256,
};
use sha2::{Digest, Sha256};

use crate::ports::tee::{AttestationReport, TeeRuntime};

/// OID for the RA-TLS attestation extension: 1.3.6.1.4.1.99999.1
///
/// Private enterprise arc (mock). In production this would be a registered OID.
pub const ATTESTATION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1];

/// Generated RA-TLS certificate bundle.
pub struct RaTlsCertificate {
    /// DER-encoded X.509 certificate
    pub cert_der: Vec<u8>,
    /// DER-encoded PKCS#8 private key
    pub key_der: Vec<u8>,
    /// The attestation report embedded in the certificate
    pub attestation: AttestationReport,
}

/// Generate a self-signed RA-TLS certificate with an embedded mock attestation report.
///
/// 1. Generates a P-256 TLS key pair
/// 2. Computes `pubkey_hash = SHA-256(tls_public_key_der)`
/// 3. Calls `TeeRuntime::generate_attestation(pubkey_hash)` to get the attestation report
/// 4. Embeds the JSON-serialized report as a custom X.509 extension
/// 5. Returns the self-signed certificate and key in DER format
pub async fn generate_ra_tls_cert(
    tee: &impl TeeRuntime,
) -> Result<RaTlsCertificate, CertError> {
    // 1. Generate P-256 TLS key pair
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| CertError::KeyGeneration(e.to_string()))?;

    // 2. Compute SHA-256 hash of the TLS public key (DER-encoded)
    let pubkey_der = key_pair.public_key_der();
    let pubkey_hash = Sha256::digest(pubkey_der);
    let pubkey_hash_b256 = B256::from_slice(&pubkey_hash);

    // 3. Generate attestation report binding the TLS public key
    let report = tee
        .generate_attestation(pubkey_hash_b256)
        .await
        .map_err(|e| CertError::Attestation(e.to_string()))?;

    // 4. Embed the JSON-serialized AttestationReport in the X.509 extension.
    //    The raw NSM document (if present) is included as a field so the client
    //    can verify it. Production would decode the CBOR COSE_Sign1 here.
    let ext_bytes = serde_json::to_vec(&report)
        .map_err(|e| CertError::Serialization(e.to_string()))?;

    let ext = CustomExtension::from_oid_content(ATTESTATION_OID, ext_bytes);

    // 5. Build self-signed certificate
    let mut params = CertificateParams::new(vec!["tee-swap.local".to_string()])
        .map_err(|e| CertError::CertGeneration(e.to_string()))?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "TEE Swap Coordinator");
    dn.push(DnType::OrganizationName, "EthSystems");
    params.distinguished_name = dn;
    params.custom_extensions = vec![ext];

    let certificate = params
        .self_signed(&key_pair)
        .map_err(|e| CertError::CertGeneration(e.to_string()))?;

    Ok(RaTlsCertificate {
        cert_der: certificate.der().to_vec(),
        key_der: key_pair.serialize_der(),
        attestation: report,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    #[error("attestation generation failed: {0}")]
    Attestation(String),

    #[error("serialization failed: {0}")]
    Serialization(String),

    #[error("certificate generation failed: {0}")]
    CertGeneration(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::mock_tee::MockTeeRuntime;
    use alloy::primitives::Address;
    use x509_parser::prelude::*;

    async fn test_cert() -> RaTlsCertificate {
        let tee = MockTeeRuntime::new(Address::repeat_byte(0x42));
        generate_ra_tls_cert(&tee).await.unwrap()
    }

    #[tokio::test]
    async fn test_generate_ra_tls_cert_produces_valid_der() {
        let ra_cert = test_cert().await;

        // Parse with x509-parser — must succeed
        let (_, cert) = X509Certificate::from_der(&ra_cert.cert_der)
            .expect("certificate should parse as valid DER");

        assert!(cert
            .subject()
            .to_string()
            .contains("TEE Swap Coordinator"));
    }

    #[tokio::test]
    async fn test_attestation_extension_present() {
        let ra_cert = test_cert().await;
        let (_, cert) = X509Certificate::from_der(&ra_cert.cert_der).unwrap();

        let oid_str = "1.3.6.1.4.1.99999.1";
        let ext = cert
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == oid_str);

        assert!(ext.is_some(), "attestation extension should be present");
    }

    #[tokio::test]
    async fn test_attestation_report_roundtrip() {
        let ra_cert = test_cert().await;
        let (_, cert) = X509Certificate::from_der(&ra_cert.cert_der).unwrap();

        let oid_str = "1.3.6.1.4.1.99999.1";
        let ext = cert
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == oid_str)
            .expect("extension should exist");

        // The extension value contains the JSON-serialized attestation report
        let report: AttestationReport =
            serde_json::from_slice(ext.value).expect("should deserialize");

        assert_eq!(report.tee_type, "mock");
        assert_eq!(report, ra_cert.attestation);
    }

    #[tokio::test]
    async fn test_pubkey_hash_matches() {
        let ra_cert = test_cert().await;
        let (_, cert) = X509Certificate::from_der(&ra_cert.cert_der).unwrap();

        // Extract the TLS public key from the certificate's SPKI
        let spki_raw = cert.public_key().raw;
        let pubkey_hash = Sha256::digest(spki_raw);
        let expected = B256::from_slice(&pubkey_hash);

        assert_eq!(ra_cert.attestation.pubkey_hash, expected);
    }
}

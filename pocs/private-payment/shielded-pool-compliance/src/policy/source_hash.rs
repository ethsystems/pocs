use std::path::Path;

use ark_bn254::Fr;

use crate::poseidon::{
    fr_from_be_bytes,
    poseidon2,
};

/// Normalizes CRLF to LF, strips trailing whitespace per line, and ensures exactly one
/// trailing newline. The canonicalization rule for `POLICY_SOURCE_HASH`, applied once.
fn canonicalize(source: &str) -> Vec<u8> {
    let normalized = source.replace("\r\n", "\n");
    let mut lines: Vec<&str> = normalized.split('\n').collect();
    while lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    let mut canonical = lines
        .iter()
        .map(|line| line.trim_end())
        .collect::<Vec<_>>()
        .join("\n");
    canonical.push('\n');
    canonical.into_bytes()
}

/// A `Poseidon1` image over the canonicalized bytes of the policy source at `path`, so
/// the in-circuit `POLICY_SOURCE_HASH` constant and this value compare as field elements.
pub fn policy_source_hash(path: &Path) -> std::io::Result<Fr> {
    let source = std::fs::read_to_string(path)?;
    let canonical = canonicalize(&source);
    let mut acc = Fr::from(0u64);
    // 31, not 32: keeps every big-endian-padded chunk below the BN254 modulus, so
    // interpreting it as an Fr is infallible by construction.
    for chunk in canonical.chunks(31) {
        let mut padded = [0u8; 32];
        padded[32 - chunk.len()..].copy_from_slice(chunk);
        acc = poseidon2(acc, fr_from_be_bytes(&padded));
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    fn write_fixture(contents: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("create tmp fixture");
        file.write_all(contents.as_bytes()).expect("write fixture");
        file
    }

    #[test]
    fn hash_is_stable_across_crlf_and_trailing_whitespace_variants() {
        let lf = write_fixture("pub global K: u32 = 1;\nfn foo() {}\n");
        let crlf = write_fixture("pub global K: u32 = 1;\r\nfn foo() {}\r\n");
        let trailing_ws = write_fixture("pub global K: u32 = 1;   \nfn foo() {}  \n");
        let no_trailing_newline = write_fixture("pub global K: u32 = 1;\nfn foo() {}");

        let hash_lf = policy_source_hash(lf.path()).expect("read lf fixture");
        let hash_crlf = policy_source_hash(crlf.path()).expect("read crlf fixture");
        let hash_ws =
            policy_source_hash(trailing_ws.path()).expect("read trailing-ws fixture");
        let hash_no_nl = policy_source_hash(no_trailing_newline.path())
            .expect("read no-newline fixture");

        assert_eq!(hash_lf, hash_crlf);
        assert_eq!(hash_lf, hash_ws);
        assert_eq!(hash_lf, hash_no_nl);
    }

    #[test]
    fn different_content_hashes_differently() {
        let a = write_fixture("pub global K: u32 = 1;\n");
        let b = write_fixture("pub global K: u32 = 2;\n");
        assert_ne!(
            policy_source_hash(a.path()).expect("read fixture a"),
            policy_source_hash(b.path()).expect("read fixture b")
        );
    }

    #[test]
    fn hash_spans_multiple_31_byte_chunks() {
        let long = write_fixture(&"x".repeat(100));
        assert!(policy_source_hash(long.path()).is_ok());
    }
}

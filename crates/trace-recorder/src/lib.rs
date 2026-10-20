//! Writes and validates JSONL demo traces, each one recorded run of a PoC scenario.
//! `SPEC.md` is the contract; `Recorder::finish` and `parse` enforce its rules.

use std::{
    borrow::{
        Borrow,
        Cow,
    },
    collections::{
        BTreeMap,
        BTreeSet,
    },
    fmt,
    fs::{
        self,
        File,
    },
    io::{
        self,
        BufWriter,
        Write,
    },
    ops::Deref,
    path::{
        Path,
        PathBuf,
    },
};

use serde::{
    Deserialize,
    Deserializer,
    Serialize,
    Serializer,
    de,
};
use serde_json::Value;

pub const SCHEMA_VERSION: u32 = 1;

/// Actions every trace may use undeclared. A PoC extends them through `Header::actions`.
const CORE_ACTIONS: [&str; 11] = [
    "onboard", "deposit", "transfer", "receive", "withdraw", "disclose", "swap",
    "redeem", "prove", "submit", "reject",
];

/// A string that borrows from the trace text whenever it holds no JSON escapes. A bare
/// `Cow<str>` would come back owned inside any `Vec` or map.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Str<'a>(Cow<'a, str>);

impl Deref for Str<'_> {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for Str<'_> {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl<'a> From<&'a str> for Str<'a> {
    fn from(s: &'a str) -> Self {
        Self(Cow::Borrowed(s))
    }
}

impl From<String> for Str<'_> {
    fn from(s: String) -> Self {
        Self(Cow::Owned(s))
    }
}

impl fmt::Display for Str<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for Str<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for Str<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Str<'de>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }

            fn visit_borrowed_str<E: de::Error>(
                self,
                s: &'de str,
            ) -> Result<Str<'de>, E> {
                Ok(Str(Cow::Borrowed(s)))
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<Str<'de>, E> {
                Ok(Str(Cow::Owned(s.to_owned())))
            }

            fn visit_string<E: de::Error>(self, s: String) -> Result<Str<'de>, E> {
                Ok(Str(Cow::Owned(s)))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

/// Bytes that travel as lowercase, `0x`-prefixed, even-length hex (rule 11). Writing
/// streams the digits; reading decodes, which is the one place a trace must own bytes.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hex<'a>(Cow<'a, [u8]>);

impl Deref for Hex<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> From<&'a [u8]> for Hex<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self(Cow::Borrowed(bytes))
    }
}

impl From<Vec<u8>> for Hex<'_> {
    fn from(bytes: Vec<u8>) -> Self {
        Self(Cow::Owned(bytes))
    }
}

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl Serialize for Hex<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Hex<'_> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = Vec<u8>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("lowercase 0x-prefixed even-length hex")
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<Vec<u8>, E> {
                let nibble = |b: u8| match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    _ => None,
                };
                s.strip_prefix("0x")
                    .filter(|digits| digits.len() % 2 == 0)
                    .and_then(|digits| {
                        digits
                            .as_bytes()
                            .chunks_exact(2)
                            .map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?))
                            .collect()
                    })
                    .ok_or_else(|| {
                        E::custom(format!(
                            "rule 11: `{s}` is not lowercase 0x-prefixed even-length hex"
                        ))
                    })
            }
        }

        deserializer
            .deserialize_str(Visitor)
            .map(|bytes| Self(Cow::Owned(bytes)))
    }
}

#[derive(Debug)]
pub struct Trace<'a> {
    pub header: Header<'a>,
    /// In run order; a step's position is its index.
    pub steps: Vec<Step<'a>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct Header<'a> {
    pub schema: u32,
    /// Repository path of the PoC, e.g. `pocs/private-payment/shielded-pool-compliance`.
    pub poc: Str<'a>,
    pub scenario: Str<'a>,
    pub title: Str<'a>,
    pub summary: Str<'a>,
    /// What the run simplifies against the PoC's spec, for a consumer to show up front.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub simplifications: Vec<Str<'a>>,
    /// True when the run used mock proofs, which no real verifier accepts.
    #[serde(default, skip_serializing_if = "is_false")]
    pub mock_proofs: bool,
    /// The test or binary that produced the trace, relative to `poc`.
    pub source: Str<'a>,
    pub map: MapRefs<'a>,
    pub chains: Vec<Chain<'a>>,
    pub assets: Vec<Asset<'a>>,
    pub personas: Vec<Persona<'a>>,
    pub observers: Vec<Observer<'a>>,
    pub fields: Vec<Field<'a>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<ActionDef<'a>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub circuits: Vec<CircuitDef<'a>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub note_domains: Vec<NoteDomain<'a>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub note_layouts: Vec<NoteLayout<'a>>,
}

/// The ethsystems/map entries the scenario demonstrates.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct MapRefs<'a> {
    pub use_case: Str<'a>,
    pub approach: Str<'a>,
    pub patterns: Vec<Str<'a>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct Chain<'a> {
    pub chain_id: u64,
    pub name: Str<'a>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct Asset<'a> {
    pub id: Str<'a>,
    pub symbol: Str<'a>,
    pub decimals: u8,
    pub chain_id: u64,
    pub address: Hex<'a>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct Persona<'a> {
    pub id: Str<'a>,
    pub label: Str<'a>,
    pub role: Str<'a>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Hex<'a>>,
    /// The persona's in-protocol public identifier, so a consumer can name it
    /// wherever a decrypted field carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_pubkey: Option<Hex<'a>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<Key<'a>>,
}

/// A throwaway secret that opens notes. Traces sync to a public repo.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct Key<'a> {
    pub id: Str<'a>,
    pub secret: Hex<'a>,
    /// What the key opens, e.g. "value notes addressed to this persona (0x01)".
    pub opens: Str<'a>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct Observer<'a> {
    pub id: Str<'a>,
    pub role: ObserverRole,
    pub label: Str<'a>,
}

/// Side-by-side matrices align observers across approaches by role, not by id.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObserverRole {
    Public,
    Counterparty,
    Regulator,
    Operator,
    Issuer,
    Other,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct Field<'a> {
    pub id: Str<'a>,
    pub label: Str<'a>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct ActionDef<'a> {
    pub id: Str<'a>,
    pub label: Str<'a>,
}

/// The names of a circuit's public inputs, in order.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct CircuitDef<'a> {
    pub id: Str<'a>,
    pub public_inputs: Vec<Str<'a>>,
}

/// A sealring 0.3 note domain.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct NoteDomain<'a> {
    pub id: Str<'a>,
    pub kem: Kem,
    /// sealring's `Domain::DOMAIN_TAG`. It is a compile-time constant there, so a
    /// consumer's decryptor must already know every tag a trace names.
    pub tag: Str<'a>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kem {
    K256,
    X25519,
    Grumpkin,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct NoteLayout<'a> {
    pub id: Str<'a>,
    pub label: Str<'a>,
    pub codec: Codec<'a>,
}

/// How a note's plaintext encodes its fields.
#[derive(Debug, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "lowercase",
    bound(deserialize = "'de: 'a")
)]
pub enum Codec<'a> {
    /// Fields at fixed offsets in a plaintext of exactly `len` bytes.
    Fixed {
        len: u32,
        fields: Vec<LayoutField<'a>>,
    },
    /// A JSON object; a counted note's `amount` member is a decimal or `0x` hex string.
    Json,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct LayoutField<'a> {
    pub name: Str<'a>,
    pub offset: u32,
    #[serde(rename = "type")]
    pub ty: FieldType,
    /// Names for sentinel values.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<Hex<'a>, Str<'a>>,
}

/// `bytes32` and `address` take 32 bytes, an address left-padded with zeros; the
/// integers are big-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    Bytes32,
    Address,
    U64,
    U128,
    U256,
}

impl FieldType {
    const fn width(self) -> u32 {
        match self {
            Self::Bytes32 | Self::Address | Self::U256 => 32,
            Self::U128 => 16,
            Self::U64 => 8,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct Step<'a> {
    pub actor: Str<'a>,
    pub action: Str<'a>,
    pub title: Str<'a>,
    /// Which persona plays an observer role in this step, e.g. `counterparty: bob`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub roles: BTreeMap<Str<'a>, Str<'a>>,
    pub artifacts: Vec<Artifact<'a>>,
    /// Observer id, then field id, for every pair the header declares.
    pub observations: BTreeMap<Str<'a>, BTreeMap<Str<'a>, Cell<'a>>>,
    /// Every persona's holdings once the step has happened.
    pub wallets: BTreeMap<Str<'a>, Vec<Balance<'a>>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct Cell<'a> {
    pub level: Level,
    pub why: Str<'a>,
    /// Artifact ids; empty exactly when `level` is `NotApplicable`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Level {
    #[serde(rename = "hidden")]
    Hidden,
    #[serde(rename = "visible")]
    Visible,
    #[serde(rename = "key-gated")]
    KeyGated,
    #[serde(rename = "inferable")]
    Inferable,
    /// The step has no such field, e.g. the amount of a cohort issuance.
    #[serde(rename = "n/a")]
    NotApplicable,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct Balance<'a> {
    pub asset: Str<'a>,
    pub kind: BalanceKind,
    /// Base units in decimal: a `u256` does not fit a JSON number.
    pub amount: Str<'a>,
    /// The notes a confidential balance sums, which a consumer decrypts to check it. An
    /// account-style balance, such as an FHE ciphertext, lists none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BalanceKind {
    Confidential,
    Public,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", bound(deserialize = "'de: 'a"))]
pub enum Artifact<'a> {
    Tx(Tx<'a>),
    Proof(Proof<'a>),
    Note(Note<'a>),
    Message(Message<'a>),
    State(State<'a>),
}

impl Artifact<'_> {
    pub const fn id(&self) -> u32 {
        match self {
            Self::Tx(a) => a.id,
            Self::Proof(a) => a.id,
            Self::Note(a) => a.id,
            Self::Message(a) => a.id,
            Self::State(a) => a.id,
        }
    }

    const fn kind(&self) -> &'static str {
        match self {
            Self::Tx(_) => "tx",
            Self::Proof(_) => "proof",
            Self::Note(_) => "note",
            Self::Message(_) => "message",
            Self::State(_) => "state",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct Tx<'a> {
    pub id: u32,
    pub chain_id: u64,
    pub from: Hex<'a>,
    pub to: Hex<'a>,
    pub method: Str<'a>,
    pub outcome: TxOutcome<'a>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<Event<'a>>,
    /// The calldata, which must carry the bytes of every proof this transaction verifies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Hex<'a>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "lowercase",
    deny_unknown_fields,
    bound(deserialize = "'de: 'a")
)]
pub enum TxOutcome<'a> {
    Confirmed {
        hash: Hex<'a>,
        block_number: u64,
        gas_used: u64,
    },
    /// The node refused the call before it was mined, so there is no hash.
    Rejected { revert: Str<'a> },
    /// Mined, then reverted: its calldata is public, and its effects are undone.
    Reverted {
        hash: Hex<'a>,
        block_number: u64,
        gas_used: u64,
        revert: Str<'a>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct Event<'a> {
    pub name: Str<'a>,
    pub args: BTreeMap<Str<'a>, Str<'a>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct Proof<'a> {
    pub id: u32,
    pub system: Str<'a>,
    pub circuit: Str<'a>,
    pub public_inputs: Vec<Hex<'a>>,
    pub bytes: Hex<'a>,
    /// True for a proof the recorded run did not generate itself.
    pub precomputed: bool,
    /// The confirmed transaction whose on-chain verifier accepted the proof, and whose
    /// calldata carries `bytes`. A consumer does not re-verify proofs; this transaction
    /// is the evidence. It may come from a later step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_by: Option<u32>,
}

/// Exactly one of `sealed` and `opened` is set (rule 5).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct Note<'a> {
    pub id: u32,
    pub label: Str<'a>,
    pub recipient: Str<'a>,
    /// The transaction or message that carried the note.
    pub carried_by: u32,
    /// The note's position within what carried it.
    pub element: u32,
    /// A key from the header opens it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<Sealed<'a>>,
    /// No key in the header opens it, e.g. a Zama KMS or Aztec PXE note, so the trace
    /// carries the plaintext and who decrypted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opened: Option<Opened<'a>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct Sealed<'a> {
    pub domain: Str<'a>,
    pub layout: Str<'a>,
    pub key: Str<'a>,
    pub aad: Hex<'a>,
    pub ciphertext: Hex<'a>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct Opened<'a> {
    /// A JSON object; one counted in a confidential balance carries a decimal `amount`.
    pub plaintext: Value,
    pub decrypted_by: Str<'a>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct Message<'a> {
    pub id: u32,
    pub channel: Str<'a>,
    pub from: Str<'a>,
    pub to: Str<'a>,
    pub body: Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "'de: 'a"))]
pub struct State<'a> {
    pub id: u32,
    pub label: Str<'a>,
    pub data: Value,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum LineRef<'t, 'a> {
    Header(&'t Header<'a>),
    Step(&'t Step<'a>),
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", bound(deserialize = "'de: 'a"))]
enum Line<'a> {
    Header(Box<Header<'a>>),
    Step(Box<Step<'a>>),
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("I/O on {}", path.display())]
    Io { path: PathBuf, source: io::Error },
    /// Rule 11 surfaces here, since a malformed hex value fails to parse.
    #[error("line {line} is not a valid trace line")]
    Json {
        line: usize,
        source: serde_json::Error,
    },
    /// `rule` numbers the rule in `SPEC.md` Section 4.2.
    #[error("rule {rule}: {detail}")]
    Invalid { rule: u8, detail: String },
    /// A note that does not open, or a balance its notes do not sum to (Section 4.3).
    #[error("section 4.3: {0}")]
    Opening(String),
}

impl Error {
    fn io(path: &Path) -> impl FnOnce(io::Error) -> Self {
        move |source| Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }

    fn in_step(self, position: usize) -> Self {
        match self {
            Self::Invalid { rule, detail } => Self::Invalid {
                rule,
                detail: format!("step {position}: {detail}"),
            },
            other => other,
        }
    }
}

fn invalid(rule: u8, detail: impl Into<String>) -> Error {
    Error::Invalid {
        rule,
        detail: detail.into(),
    }
}

/// Collects a trace and writes it only once it validates, so a scenario that panics
/// part-way leaves no file behind.
#[derive(Debug)]
pub struct Recorder<'a> {
    trace: Trace<'a>,
    next_id: u32,
}

impl<'a> Recorder<'a> {
    pub fn new(header: Header<'a>) -> Self {
        Self {
            trace: Trace {
                header,
                steps: Vec::new(),
            },
            next_id: 0,
        }
    }

    /// The next artifact id.
    pub fn next_id(&mut self) -> u32 {
        self.next_id += 1;
        self.next_id
    }

    pub fn header(&self) -> &Header<'a> {
        &self.trace.header
    }

    pub fn steps(&self) -> &[Step<'a>] {
        &self.trace.steps
    }

    pub fn push(&mut self, step: Step<'a>) {
        self.trace.steps.push(step);
    }

    /// Runs every check a consumer runs: the rules of Section 4.2, then Section 4.3
    /// with `open`, which the PoC supplies because sealring fixes the domain tag at
    /// compile time.
    pub fn check(
        &self,
        open: impl FnMut(&NoteDomain<'_>, &Key<'_>, &Sealed<'_>) -> Option<Vec<u8>>,
    ) -> Result<(), Error> {
        validate(&self.trace)?;
        check_notes(&self.trace, open)
    }

    /// Checks, then streams to a sibling `.tmp` file and renames it into place, so a
    /// reader never sees a half-written trace.
    pub fn finish(
        self,
        path: &Path,
        open: impl FnMut(&NoteDomain<'_>, &Key<'_>, &Sealed<'_>) -> Option<Vec<u8>>,
    ) -> Result<(), Error> {
        self.check(open)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(Error::io(parent))?;
        }
        let tmp = path.with_extension("jsonl.tmp");
        write_jsonl(&self.trace, &tmp).map_err(Error::io(&tmp))?;
        fs::rename(&tmp, path).map_err(Error::io(path))
    }
}

fn write_jsonl(trace: &Trace<'_>, path: &Path) -> io::Result<()> {
    let mut out = BufWriter::new(File::create(path)?);
    let lines = std::iter::once(LineRef::Header(&trace.header))
        .chain(trace.steps.iter().map(LineRef::Step));
    for line in lines {
        serde_json::to_writer(&mut out, &line)?;
        out.write_all(b"\n")?;
    }
    out.flush()
}

/// Parses and validates a trace. Strings borrow from `jsonl` wherever they can.
pub fn parse(jsonl: &str) -> Result<Trace<'_>, Error> {
    let mut header = None;
    let mut steps = Vec::new();
    for (i, text) in jsonl
        .lines()
        .enumerate()
        .filter(|(_, t)| !t.trim().is_empty())
    {
        let line = i + 1;
        match serde_json::from_str(text).map_err(|source| Error::Json { line, source })? {
            Line::Header(h) if header.is_none() => header = Some(*h),
            Line::Header(_) => {
                return Err(invalid(1, format!("line {line}: a second header")));
            }
            Line::Step(_) if header.is_none() => {
                return Err(invalid(1, format!("line {line}: a step before the header")));
            }
            Line::Step(s) => steps.push(*s),
        }
    }
    let header = header.ok_or_else(|| invalid(1, "no header"))?;
    let trace = Trace { header, steps };
    validate(&trace)?;
    Ok(trace)
}

/// What the header declares, for checking every step against it.
struct Declared<'t> {
    personas: BTreeSet<&'t str>,
    observers: BTreeSet<&'t str>,
    fields: BTreeSet<&'t str>,
    chains: BTreeSet<u64>,
    assets: BTreeSet<&'t str>,
    actions: BTreeSet<&'t str>,
    domains: BTreeSet<&'t str>,
    circuits: BTreeMap<&'t str, usize>,
    /// `(persona, key)`: a sealed note names a key of its recipient.
    keys: BTreeSet<(&'t str, &'t str)>,
    layouts: BTreeMap<&'t str, &'t NoteLayout<'t>>,
}

impl<'t> Declared<'t> {
    fn new(h: &'t Header<'t>) -> Self {
        Self {
            personas: h.personas.iter().map(|p| &*p.id).collect(),
            observers: h.observers.iter().map(|o| &*o.id).collect(),
            fields: h.fields.iter().map(|f| &*f.id).collect(),
            chains: h.chains.iter().map(|c| c.chain_id).collect(),
            assets: h.assets.iter().map(|a| &*a.id).collect(),
            actions: CORE_ACTIONS
                .into_iter()
                .chain(h.actions.iter().map(|a| &*a.id))
                .collect(),
            domains: h.note_domains.iter().map(|d| &*d.id).collect(),
            circuits: h
                .circuits
                .iter()
                .map(|c| (&*c.id, c.public_inputs.len()))
                .collect(),
            keys: h
                .personas
                .iter()
                .flat_map(|p| p.keys.iter().map(|k| (&*p.id, &*k.id)))
                .collect(),
            layouts: h.note_layouts.iter().map(|l| (&*l.id, l)).collect(),
        }
    }
}

/// Artifacts recorded so far: a reference may point back across steps, never forward.
type Seen<'t> = BTreeMap<u32, &'t Artifact<'t>>;

/// Checks every rule of `SPEC.md` a parsed `Trace` can still break. Rule 1 is a
/// property of the file, which `parse` checks, and rule 11 is a property of `Hex`.
fn validate<'t>(trace: &'t Trace<'t>) -> Result<(), Error> {
    validate_header(&trace.header)?;
    let declared = Declared::new(&trace.header);
    let mut seen = Seen::new();
    for (position, step) in trace.steps.iter().enumerate() {
        validate_step(step, &declared, &mut seen).map_err(|e| e.in_step(position))?;
    }
    // A proof's `verified_by` may name a later step's transaction, so proofs are
    // checked once every artifact is seen.
    for (position, step) in trace.steps.iter().enumerate() {
        for artifact in &step.artifacts {
            if let Artifact::Proof(proof) = artifact {
                validate_proof(proof, &declared, &seen)
                    .map_err(|e| e.in_step(position))?;
            }
        }
    }
    Ok(())
}

fn validate_proof(
    proof: &Proof<'_>,
    declared: &Declared<'_>,
    seen: &Seen<'_>,
) -> Result<(), Error> {
    if let Some(&names) = declared.circuits.get(&*proof.circuit)
        && names != proof.public_inputs.len()
    {
        return Err(invalid(
            13,
            format!(
                "proof {} has {} public inputs; circuit `{}` names {names}",
                proof.id,
                proof.public_inputs.len(),
                proof.circuit
            ),
        ));
    }
    let Some(tx) = proof.verified_by else {
        return Ok(());
    };
    let Some(Artifact::Tx(verifier)) = seen.get(&tx) else {
        return Err(invalid(
            8,
            format!("proof {} verified_by {tx} is not a recorded tx", proof.id),
        ));
    };
    if !matches!(verifier.outcome, TxOutcome::Confirmed { .. }) {
        return Err(invalid(
            8,
            format!(
                "proof {} verified_by {tx}, which is not confirmed",
                proof.id
            ),
        ));
    }
    let carried = !proof.bytes.is_empty()
        && verifier.input.as_deref().is_some_and(|input| {
            input.windows(proof.bytes.len()).any(|w| w == &*proof.bytes)
        });
    if !carried {
        return Err(invalid(
            8,
            format!("tx {tx}'s input does not carry proof {}'s bytes", proof.id),
        ));
    }
    Ok(())
}

fn validate_header(h: &Header<'_>) -> Result<(), Error> {
    if h.schema != SCHEMA_VERSION {
        return Err(invalid(
            12,
            format!("schema {} is not {SCHEMA_VERSION}", h.schema),
        ));
    }
    unique("personas", h.personas.iter().map(|p| &*p.id))?;
    unique("observers", h.observers.iter().map(|o| &*o.id))?;
    unique("fields", h.fields.iter().map(|f| &*f.id))?;
    unique("assets", h.assets.iter().map(|a| &*a.id))?;
    unique("actions", h.actions.iter().map(|a| &*a.id))?;
    unique("circuits", h.circuits.iter().map(|c| &*c.id))?;
    unique("note_domains", h.note_domains.iter().map(|d| &*d.id))?;
    unique("note_layouts", h.note_layouts.iter().map(|l| &*l.id))?;
    for persona in &h.personas {
        unique(
            &format!("persona `{}` keys", persona.id),
            persona.keys.iter().map(|k| &*k.id),
        )?;
    }
    if let Some(action) = h.actions.iter().find(|a| CORE_ACTIONS.contains(&&*a.id)) {
        return Err(invalid(
            12,
            format!("action `{}` is already core", action.id),
        ));
    }
    let chains: BTreeSet<u64> = h.chains.iter().map(|c| c.chain_id).collect();
    if chains.len() != h.chains.len() {
        return Err(invalid(12, "a chain id repeats"));
    }
    if let Some(asset) = h.assets.iter().find(|a| !chains.contains(&a.chain_id)) {
        return Err(invalid(
            12,
            format!("asset `{}` is on an undeclared chain", asset.id),
        ));
    }
    for layout in &h.note_layouts {
        let Codec::Fixed { len, fields } = &layout.codec else {
            continue;
        };
        unique(
            &format!("layout `{}` fields", layout.id),
            fields.iter().map(|f| &*f.name),
        )?;
        if let Some(field) = fields.iter().find(|f| {
            f.offset
                .checked_add(f.ty.width())
                .is_none_or(|end| end > *len)
        }) {
            return Err(invalid(
                12,
                format!("layout `{}` field `{}` overruns it", layout.id, field.name),
            ));
        }
    }
    Ok(())
}

fn validate_step<'t>(
    step: &'t Step<'t>,
    declared: &Declared<'_>,
    seen: &mut Seen<'t>,
) -> Result<(), Error> {
    if !declared.personas.contains(&*step.actor) {
        return Err(invalid(
            2,
            format!("actor `{}` is not a persona", step.actor),
        ));
    }
    if !declared.actions.contains(&*step.action) {
        return Err(invalid(
            2,
            format!("action `{}` is not declared", step.action),
        ));
    }
    if let Some((observer, persona)) = step.roles.iter().find(|(observer, persona)| {
        !declared.observers.contains(&***observer)
            || !declared.personas.contains(&***persona)
    }) {
        return Err(invalid(
            2,
            format!("role `{observer}: {persona}` is not declared"),
        ));
    }
    for artifact in &step.artifacts {
        if seen.insert(artifact.id(), artifact).is_some() {
            return Err(invalid(3, format!("artifact id {} repeats", artifact.id())));
        }
    }
    for artifact in &step.artifacts {
        validate_artifact(artifact, declared, seen)?;
    }
    validate_observations(step, declared, seen)?;
    validate_wallets(step, declared, seen)
}

fn validate_artifact(
    artifact: &Artifact<'_>,
    declared: &Declared<'_>,
    seen: &Seen<'_>,
) -> Result<(), Error> {
    match artifact {
        Artifact::Tx(tx) if !declared.chains.contains(&tx.chain_id) => Err(invalid(
            4,
            format!("tx {} is on an undeclared chain", tx.id),
        )),
        Artifact::Note(note) => validate_note(note, declared, seen),
        Artifact::Message(message) => match [&message.from, &message.to]
            .into_iter()
            .find(|end| !declared.personas.contains(&***end))
        {
            Some(end) => Err(invalid(
                2,
                format!("message {} end `{end}` is not a persona", message.id),
            )),
            None => Ok(()),
        },
        Artifact::Tx(_) | Artifact::Proof(_) | Artifact::State(_) => Ok(()),
    }
}

fn validate_note(
    note: &Note<'_>,
    declared: &Declared<'_>,
    seen: &Seen<'_>,
) -> Result<(), Error> {
    if !declared.personas.contains(&*note.recipient) {
        return Err(invalid(
            5,
            format!("note {} recipient is not a persona", note.id),
        ));
    }
    refers_to(seen, note.carried_by, &["tx", "message"])?;
    match (&note.sealed, &note.opened) {
        (Some(sealed), None)
            if !declared.domains.contains(&*sealed.domain)
                || !declared.layouts.contains_key(&*sealed.layout)
                || !declared.keys.contains(&(&*note.recipient, &*sealed.key)) =>
        {
            Err(invalid(
                5,
                format!(
                    "note {} names an undeclared domain or layout, or a key its recipient lacks",
                    note.id
                ),
            ))
        }
        (None, Some(opened)) if !opened.plaintext.is_object() => Err(invalid(
            5,
            format!("note {} plaintext is not an object", note.id),
        )),
        (None, Some(opened)) if !declared.personas.contains(&*opened.decrypted_by) => {
            Err(invalid(
                5,
                format!("note {} decrypted_by is not a persona", note.id),
            ))
        }
        (Some(_), None) | (None, Some(_)) => Ok(()),
        _ => Err(invalid(
            5,
            format!("note {} must be exactly one of sealed and opened", note.id),
        )),
    }
}

fn validate_observations(
    step: &Step<'_>,
    declared: &Declared<'_>,
    seen: &Seen<'_>,
) -> Result<(), Error> {
    if !step
        .observations
        .keys()
        .map(|o| &**o)
        .eq(declared.observers.iter().copied())
    {
        return Err(invalid(
            6,
            "observations do not cover exactly the observers",
        ));
    }
    for (observer, row) in &step.observations {
        if !row.keys().map(|f| &**f).eq(declared.fields.iter().copied()) {
            return Err(invalid(
                6,
                format!("observer `{observer}` does not cover exactly the fields"),
            ));
        }
        for (field, cell) in row {
            if (cell.level == Level::NotApplicable) != cell.evidence.is_empty() {
                return Err(invalid(
                    7,
                    format!(
                        "cell `{observer}.{field}` must cite evidence unless it is n/a, and only then"
                    ),
                ));
            }
            if let Some(id) = cell.evidence.iter().find(|id| !seen.contains_key(id)) {
                return Err(invalid(
                    8,
                    format!(
                        "cell `{observer}.{field}` cites {id}, which is not recorded yet"
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn validate_wallets(
    step: &Step<'_>,
    declared: &Declared<'_>,
    seen: &Seen<'_>,
) -> Result<(), Error> {
    if !step
        .wallets
        .keys()
        .map(|p| &**p)
        .eq(declared.personas.iter().copied())
    {
        return Err(invalid(9, "wallets do not cover exactly the personas"));
    }
    let mut listed = BTreeSet::new();
    for (persona, balances) in &step.wallets {
        for balance in balances {
            let at = || format!("wallet `{persona}` balance in `{}`", balance.asset);
            if !declared.assets.contains(&*balance.asset) {
                return Err(invalid(9, format!("{}: undeclared asset", at())));
            }
            if !is_decimal(&balance.amount) {
                return Err(invalid(9, format!("{}: amount is not decimal", at())));
            }
            if matches!(balance.kind, BalanceKind::Public) && !balance.notes.is_empty() {
                return Err(invalid(
                    10,
                    format!("{}: a public balance lists notes", at()),
                ));
            }
            for id in &balance.notes {
                let Some(Artifact::Note(note)) = seen.get(id) else {
                    return Err(invalid(
                        10,
                        format!("{} lists {id}, which is not a recorded note", at()),
                    ));
                };
                if !listed.insert(*id) {
                    return Err(invalid(
                        10,
                        format!("{}: note {id} is listed twice", at()),
                    ));
                }
                if note.recipient != *persona {
                    return Err(invalid(
                        10,
                        format!(
                            "{}: note {id} is addressed to `{}`",
                            at(),
                            note.recipient
                        ),
                    ));
                }
                if !note_has_amount(note, &declared.layouts) {
                    return Err(invalid(
                        10,
                        format!("{}: note {id} carries no `amount`", at()),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn note_has_amount(note: &Note<'_>, layouts: &BTreeMap<&str, &NoteLayout<'_>>) -> bool {
    match (&note.sealed, &note.opened) {
        (Some(sealed), _) => {
            layouts
                .get(&*sealed.layout)
                .is_some_and(|layout| match &layout.codec {
                    Codec::Fixed { fields, .. } => fields.iter().any(|f| {
                        &*f.name == "amount"
                            && matches!(
                                f.ty,
                                FieldType::U64 | FieldType::U128 | FieldType::U256
                            )
                    }),
                    // The member is inside the ciphertext, so only opening the note checks it.
                    Codec::Json => true,
                })
        }
        (None, Some(opened)) => opened
            .plaintext
            .get("amount")
            .and_then(Value::as_str)
            .is_some_and(is_decimal),
        (None, None) => false,
    }
}

/// Opens every sealed note with `open`, which returns the plaintext or `None`, and
/// checks that each confidential balance equals the notes it lists (Section 4.3).
// ponytail: amounts as u128, a big-integer sum if a PoC records more than 2^128 base units
pub fn check_notes(
    trace: &Trace<'_>,
    mut open: impl FnMut(&NoteDomain<'_>, &Key<'_>, &Sealed<'_>) -> Option<Vec<u8>>,
) -> Result<(), Error> {
    let h = &trace.header;
    let fail = |detail: String| Error::Opening(detail);
    let mut amounts = BTreeMap::new();
    for note in trace
        .steps
        .iter()
        .flat_map(|s| &s.artifacts)
        .filter_map(|a| match a {
            Artifact::Note(note) => Some(note),
            _ => None,
        })
    {
        let amount = match (&note.sealed, &note.opened) {
            (Some(sealed), _) => {
                let domain = h.note_domains.iter().find(|d| d.id == sealed.domain);
                let layout = h.note_layouts.iter().find(|l| l.id == sealed.layout);
                let key = h
                    .personas
                    .iter()
                    .find(|p| p.id == note.recipient)
                    .and_then(|p| p.keys.iter().find(|k| k.id == sealed.key));
                let (Some(domain), Some(layout), Some(key)) = (domain, layout, key)
                else {
                    return Err(fail(format!(
                        "note {} names something undeclared",
                        note.id
                    )));
                };
                let plaintext = open(domain, key, sealed).ok_or_else(|| {
                    fail(format!("note {} does not open under its key", note.id))
                })?;
                read_amount(&layout.codec, &plaintext)
                    .map_err(|detail| fail(format!("note {}: {detail}", note.id)))?
            }
            (None, Some(opened)) => match opened.plaintext.get("amount") {
                None => None,
                Some(value) => Some(
                    json_amount(value)
                        .map_err(|detail| fail(format!("note {}: {detail}", note.id)))?,
                ),
            },
            (None, None) => {
                return Err(fail(format!(
                    "note {} is neither sealed nor opened",
                    note.id
                )));
            }
        };
        amounts.insert(note.id, amount);
    }
    for (position, step) in trace.steps.iter().enumerate() {
        for (persona, balances) in &step.wallets {
            for balance in balances.iter().filter(|b| !b.notes.is_empty()) {
                let mut sum = 0u128;
                for id in &balance.notes {
                    let amount = amounts.get(id).copied().flatten().ok_or_else(|| {
                        fail(format!("step {position}: note {id} carries no amount"))
                    })?;
                    sum = sum.checked_add(amount).ok_or_else(|| {
                        fail(format!(
                            "step {position}: wallet `{persona}` overflows u128"
                        ))
                    })?;
                }
                if balance.amount.parse::<u128>().ok() != Some(sum) {
                    return Err(fail(format!(
                        "step {position}: wallet `{persona}` holds {} but its notes sum to {sum}",
                        balance.amount
                    )));
                }
            }
        }
    }
    Ok(())
}

/// A plaintext's `amount`, if its layout has one.
fn read_amount(codec: &Codec<'_>, plaintext: &[u8]) -> Result<Option<u128>, String> {
    match codec {
        Codec::Fixed { len, fields } => {
            if plaintext.len() != *len as usize {
                return Err(format!("plaintext is {} bytes, not {len}", plaintext.len()));
            }
            let Some(field) = fields.iter().find(|f| &*f.name == "amount") else {
                return Ok(None);
            };
            let start = field.offset as usize;
            let bytes = plaintext
                .get(start..start + field.ty.width() as usize)
                .ok_or("amount overruns the plaintext")?;
            let (high, low) = bytes.split_at(bytes.len().saturating_sub(16));
            if high.iter().any(|b| *b != 0) {
                return Err("amount exceeds u128".into());
            }
            Ok(Some(
                low.iter().fold(0u128, |acc, b| acc << 8 | u128::from(*b)),
            ))
        }
        Codec::Json => {
            let value: Value = serde_json::from_slice(plaintext)
                .map_err(|_| "plaintext is not JSON".to_string())?;
            let object = value.as_object().ok_or("plaintext is not a JSON object")?;
            object.get("amount").map(json_amount).transpose()
        }
    }
}

/// A decimal or `0x` hex string.
fn json_amount(value: &Value) -> Result<u128, String> {
    let text = value.as_str().ok_or("amount is not a string")?;
    match text.strip_prefix("0x") {
        Some(hex) => u128::from_str_radix(hex, 16).ok(),
        None if is_decimal(text) => text.parse().ok(),
        None => None,
    }
    .ok_or_else(|| format!("amount `{text}` is not a decimal or hex u128"))
}

const fn is_false(value: &bool) -> bool {
    !*value
}

fn refers_to(seen: &Seen<'_>, id: u32, kinds: &[&str]) -> Result<(), Error> {
    let Some(artifact) = seen.get(&id) else {
        return Err(invalid(8, format!("{id} is not recorded yet")));
    };
    if kinds.contains(&artifact.kind()) {
        Ok(())
    } else {
        Err(invalid(8, format!("{id} is not a {}", kinds.join(" or "))))
    }
}

fn unique<'t>(what: &str, mut ids: impl Iterator<Item = &'t str>) -> Result<(), Error> {
    let mut seen = BTreeSet::new();
    match ids.find(|id| !seen.insert(*id)) {
        Some(id) => Err(invalid(12, format!("{what}: id `{id}` repeats"))),
        None => Ok(()),
    }
}

fn is_decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

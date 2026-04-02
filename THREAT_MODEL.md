# Threat Model

This document describes the threat model for shadowforge-rs and the mitigations
implemented for each threat class. It is a living document — each Phase adds
mitigations and this document is updated to reflect them.

**Adversary assumption**: Nation-state level. Capable of automated mass
steganalysis, infrastructure-level traffic interception, legal compulsion
across jurisdictions, endpoint compromise via malware or hardware implants,
and stylometric authorship attribution.

---

## Threat 1: Automated Mass Steganalysis

**Description**: Nation-states (GFW, GCHQ, NSA) operate steganalysis pipelines
at infrastructure scale. Tools include Aletheia, StegExpose, and custom
CNN-based detectors trained on known steganographic signatures. They apply
chi-square analysis, RS analysis, Sample Pair analysis, and model-based
detection (identifying covers that don't match their claimed camera model).

**Mitigations in shadowforge-rs**:

- `AdaptiveEmbedder`: STC-inspired adversarial permutation optimisation.
  Minimises chi-square score, RS residual, and Sample Pair asymmetry by
  searching for the embedding permutation (keyed from the crypto key) that
  minimises all three scores simultaneously.
- `CoverProfileMatcher`: Matches JPEG quantisation tables and noise floor
  statistics to a known camera model database. Defeats detectors that check
  "does this JPEG's fingerprint match its claimed device?"
- `CompressionSurvivableEmbedder`: Embeds only in DCT coefficient positions
  that survive the target platform's recompression, preventing payload
  destruction and ensuring the cover behaves statistically like a normal
  platform upload.
- `CorpusEmbedder`: For maximum stealth, selects a pre-existing public image
  whose natural bit pattern already encodes (or nearly encodes) the payload.
  A perfect match requires zero modification — the cover is a real, unmodified
  public image. Steganalysis cannot flag an unmodified file.

**Residual risk**: A sufficiently large corpus of training data for an
adversary's CNN could potentially identify the permutation pattern used by
`AdaptiveEmbedder` as a new class. Mitigation: vary the embedding profile
per session and prefer `CorpusEmbedder` for highest-risk communications.

---

## Threat 2: Compelled Decryption / Rubber Hose

**Description**: Border guards, customs officials, or secret police with
legal authority to compel key disclosure. "Provide your decryption keys or
you will not be permitted to leave / you will be detained."

**Mitigations in shadowforge-rs**:

- `DeniableEmbedder`: Two payloads embedded in one cover. Key A decrypts an
  innocent decoy payload. Key B decrypts the real payload. The cover is
  mathematically identical regardless of which key is presented — there is no
  bit pattern that reveals a second payload exists. Under duress, surrender Key A.
- `PanicWiper`: A hidden CLI command (`panic`) that performs a 3-pass overwrite
  of all configured key files and exits `0` silently with no output. To an
  observer, it looks like a failed extraction attempt. Designed for use when
  device seizure is imminent.
- `TimeLockService`: Payloads that cannot be decrypted before a specified time,
  even under compulsion. Useful for: source protection (journalist cannot
  decrypt until story goes live), dead man's switch, and border crossing
  (payload cannot be read during transit).

**Residual risk**: Deniability does not hold if the adversary obtains both
keys. Rubber hose attacks can extract both keys if the operator is subjected
to sufficient coercion. Physical security of the operator remains essential.

---

## Threat 3: Traffic Analysis and Pattern Recognition

**Description**: Even without breaking cryptography or steganography, a
nation-state can observe communication patterns. Person A sent a JPEG to
Person B, who sent one to Person C, who sent one to a known journalist. The
content is invisible but the network graph is the message.

**Mitigations in shadowforge-rs**:

- `DeadDropEncoder` (dead drop mode): Generates stego covers optimised for
  posting to public platforms (Instagram, Imgur, Telegram, etc.). The sender
  posts publicly; the recipient retrieves from a public URL. No direct
  file transfer between parties. No network metadata linking sender to
  recipient. The adversary sees an anonymous post to a public platform.
- Platform-aware compression-survivable embedding ensures the payload
  survives the platform's recompression pass intact.
- `RetrievalManifest`: Shared out-of-band (via a separate channel) — contains
  only the platform and URL, not the key or technique.

**Residual risk**: Metadata on public platforms (upload time, account
activity patterns) may still leak timing information. Use accounts with no
identifying information and vary posting times.

---

## Threat 4: Endpoint Compromise

**Description**: Nation-state adversaries plant malware, use hardware implants,
or have physical access to the device. They may keylog, screen-capture, or
exfiltrate files as they're written.

**Mitigations in shadowforge-rs**:

- `AmnesiaPipeline` (amnesiac mode, `--amnesia`): The entire embed/extract
  pipeline runs in memory only. Input from stdin, output to stdout. No temp
  files, no logs, no crash dumps. Key material never touches the filesystem.
  Uses `std::io::pipe()` (stable 1.87) for stage connection.
- `ZeroizeOnDrop` throughout: All key material and plaintext payloads are
  zeroed in memory immediately after use. Reduces the window for memory
  forensics.
- `#[profile.release] panic = "abort"`: No unwinding on panic — reduces
  risk of partial state being left in memory.

**Residual risk**: A kernel-level implant or hardware implant can capture
stdin/stdout regardless of amnesiac mode. Amnesiac mode protects against
filesystem forensics and user-space memory analysis, not against rootkits.

---

## Threat 5: Legal and Jurisdictional Pressure

**Description**: Files seized in one jurisdiction, keys held in another,
shards distributed across multiple countries. Legal compulsion via MLAT
(Mutual Legal Assistance Treaty) requests, subpoenas, or local legal orders.

**Mitigations in shadowforge-rs**:

- Geographic threshold distribution (`--geo-manifest`): Annotates K-of-N
  shards with jurisdictional metadata. Reconstruction requires physical or
  legal access to shard holders across multiple jurisdictions simultaneously.
  The `recovery_complexity_score` function produces a human-readable summary
  estimating legal coordination time.
- K-of-N by design: Even without geographic distribution, reconstruction
  requires obtaining `K` of `N` shards. Shard holders in different countries
  each hold only a partial, useless fragment.
- `CanaryService`: An (N+1)th canary shard in a honeypot location. If an
  adversary attempts to use it for reconstruction (which will fail), the
  journalist is notified via a configurable URL — early warning that the
  distribution has been compromised.

**Residual risk**: MLAT requests, while slow, are real. For communications
requiring years of protection, consider that jurisdictions may change their
legal landscape. Geographic distribution is a delay tactic, not an absolute
protection.

---

## Threat 6: Stylometric Source Identification

**Description**: Intelligence agencies use authorship attribution tools to
identify individuals from writing style — word frequency, sentence length
distribution, rare vocabulary, punctuation patterns. Even an encrypted,
stegographically hidden document can expose its author if decrypted.

**Mitigations in shadowforge-rs**:

- `StyloScrubber` (`--scrub-style` on `embed`): Normalises text payload
  before embedding. Replaces rare vocabulary with common synonyms,
  normalises sentence lengths toward a target average, standardises
  punctuation and contractions. Uses a bundled word-frequency table derived
  from a large public corpus — no network calls, no LLM.
- Operates on grapheme clusters (Unicode-safe) and falls back gracefully
  for non-Latin scripts.

**Residual risk**: Semantic content may still implicitly identify the author
(knowledge of specific internal facts, access to specific documents). Scrubbing
normalises style, not content. Sources must still consider what the content
itself reveals about who could have written it.

---

## Threat 7: Internal Leak Attribution (Journalist-Side)

**Description**: A journalist distributes the same cover template to multiple
potential sources for a covert channel. One source leaks the cover template
to the adversary. The journalist needs to identify which source leaked it.

**Note**: This threat is the inverse of most — it protects the journalist's
tradecraft, not the source's communication.

**Mitigations in shadowforge-rs**:

- `ForensicWatermarker` (`watermark tripwire` subcommand): Embeds a unique,
  imperceptible LSB permutation in each copy of the cover, keyed from a
  per-recipient `WatermarkTripwireTag`. `identify_recipient` can match a
  leaked copy to the specific recipient.

**Residual risk**: Tripwire watermarks do not survive aggressive platform
recompression (below JPEG quality ~90). Not suitable for leak attribution
when the leaked copy has passed through a platform that recompresses images.

---

## Residual Risks Across All Threats

- **Human factors**: No cryptographic or steganographic system protects
  against an operator who voluntarily discloses information under sufficient
  pressure, blackmail, or inducement.
- **Physical surveillance**: If an adversary is physically watching the
  operator's screen, no software mitigation applies.
- **Implementation bugs**: Until an external audit is completed (Phase 18),
  implementation errors may undermine otherwise sound designs.
- **Quantum timeline**: ML-KEM and ML-DSA are designed to resist quantum
  computers. However, "harvest now, decrypt later" attacks mean communications
  made today will be exposed if a sufficiently powerful quantum computer
  is built before the key material is destroyed. Use short key lifetimes.

---

*Last updated: March 2026 | Pre-audit — see SECURITY.md*

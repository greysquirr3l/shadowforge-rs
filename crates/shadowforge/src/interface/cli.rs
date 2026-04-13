//! CLI command definitions — clap derive API.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

/// shadowforge — quantum-resistant steganography toolkit.
#[derive(Parser, Debug)]
#[command(
    name = "shadowforge",
    version,
    about = "Quantum-resistant steganography toolkit",
    long_about = None,
    propagate_version = true
)]
pub struct Cli {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Top-level subcommands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Print version and git SHA.
    Version,

    /// Key generation and signing operations.
    Keygen(KeygenArgs),

    /// Embed a payload into a cover medium.
    Embed(EmbedArgs),

    /// Extract a hidden payload from a stego cover.
    Extract(ExtractArgs),

    /// Distribute a payload across multiple covers.
    #[command(name = "embed-distributed")]
    EmbedDistributed(EmbedDistributedArgs),

    /// Reconstruct a payload from distributed stego covers.
    #[command(name = "extract-distributed")]
    ExtractDistributed(ExtractDistributedArgs),

    /// Analyse a cover for capacity and detectability.
    #[command(name = "analyse")]
    Analyse(AnalyseArgs),

    /// Pack/unpack archive bundles.
    Archive(ArchiveArgs),

    /// Scrub text of stylometric fingerprints.
    Scrub(ScrubArgs),

    /// Dead drop: encode payload for public platform posting.
    #[command(name = "dead-drop")]
    DeadDrop(DeadDropArgs),

    /// Time-lock puzzle operations.
    #[command(name = "time-lock")]
    TimeLock(TimeLockArgs),

    /// Forensic watermark operations.
    Watermark(WatermarkArgs),

    /// Corpus index operations.
    Corpus(CorpusArgs),

    /// Emergency wipe (hidden).
    #[command(hide = true)]
    Panic(PanicArgs),

    /// Generate shell completions.
    Completions(CompletionsArgs),

    /// Symmetric cipher operations (AES-256-GCM).
    Cipher(CipherArgs),
}

// ─── Value enums ──────────────────────────────────────────────────────────────

/// Key algorithm.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Algorithm {
    /// ML-KEM-1024 key encapsulation.
    Kyber1024,
    /// ML-DSA-87 digital signature.
    Dilithium3,
}

/// Steganographic technique.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Technique {
    /// LSB substitution in PNG/BMP images.
    Lsb,
    /// DCT coefficient modulation in JPEG.
    Dct,
    /// Palette index substitution for indexed images.
    Palette,
    /// LSB substitution in WAV audio.
    #[value(name = "lsb-audio")]
    LsbAudio,
    /// Phase encoding in WAV audio.
    Phase,
    /// Echo hiding in WAV audio.
    Echo,
    /// Zero-width Unicode characters in text.
    #[value(name = "zero-width")]
    ZeroWidth,
    /// PDF content stream LSB.
    #[value(name = "pdf-stream")]
    PdfStream,
    /// PDF metadata embedding.
    #[value(name = "pdf-meta")]
    PdfMeta,
    /// Corpus-based zero-modification selection.
    Corpus,
}

/// Embedding profile.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Profile {
    /// Default — no detectability constraint.
    Standard,
    /// Adaptive — bounded detectability budget.
    Adaptive,
    /// Compression-survivable for a target platform.
    Survivable,
}

/// Target platform.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Platform {
    /// Instagram JPEG recompression.
    Instagram,
    /// Twitter/X JPEG recompression.
    Twitter,
    /// `WhatsApp` JPEG recompression.
    Whatsapp,
    /// Telegram JPEG recompression.
    Telegram,
    /// Imgur JPEG recompression.
    Imgur,
}

/// Archive format.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ArchiveFormat {
    /// ZIP archive.
    Zip,
    /// TAR archive.
    Tar,
    /// Gzipped TAR archive.
    #[value(name = "tar-gz")]
    TarGz,
}

// ─── Subcommand argument structs ──────────────────────────────────────────────

/// Arguments for `keygen`.
#[derive(Parser, Debug)]
pub struct KeygenArgs {
    /// Keygen sub-operation.
    #[command(subcommand)]
    pub subcmd: Option<KeygenSubcommand>,
    /// Algorithm to use.
    #[arg(long, value_enum)]
    pub algorithm: Option<Algorithm>,
    /// Output directory for key files.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

/// `keygen` sub-operations.
#[derive(Subcommand, Debug)]
pub enum KeygenSubcommand {
    /// Sign an input file with an ML-DSA secret key.
    Sign {
        /// Input file to sign.
        #[arg(long)]
        input: PathBuf,
        /// Secret signing key file.
        #[arg(long)]
        secret_key: PathBuf,
        /// Output detached signature file.
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a detached signature with an ML-DSA public key.
    Verify {
        /// Signed input file.
        #[arg(long)]
        input: PathBuf,
        /// Public verification key file.
        #[arg(long)]
        public_key: PathBuf,
        /// Detached signature file.
        #[arg(long)]
        signature: PathBuf,
    },
}

/// Arguments for `embed`.
#[derive(Parser, Debug)]
pub struct EmbedArgs {
    /// Path to the payload file.
    #[arg(long)]
    pub input: PathBuf,
    /// Path to the cover medium (omit for `--amnesia`).
    #[arg(long)]
    pub cover: Option<PathBuf>,
    /// Output path for the stego file.
    #[arg(long)]
    pub output: PathBuf,
    /// Steganographic technique.
    #[arg(long, value_enum)]
    pub technique: Technique,
    /// Embedding profile.
    #[arg(long, value_enum, default_value = "standard")]
    pub profile: Profile,
    /// Target platform (required when profile = survivable).
    #[arg(long, value_enum)]
    pub platform: Option<Platform>,
    /// Amnesiac mode: read cover from stdin, write stego to stdout.
    #[arg(long)]
    pub amnesia: bool,
    /// Scrub text payload before embedding.
    #[arg(long)]
    pub scrub_style: bool,
    /// Enable deniable dual-payload embedding.
    #[arg(long)]
    pub deniable: bool,
    /// Decoy payload path (used with `--deniable`).
    #[arg(long)]
    pub decoy_payload: Option<PathBuf>,
    /// Decoy key path (used with `--deniable`).
    #[arg(long)]
    pub decoy_key: Option<PathBuf>,
    /// Primary key path (used with `--deniable`).
    #[arg(long)]
    pub key: Option<PathBuf>,
}

/// Arguments for `extract`.
#[derive(Parser, Debug)]
pub struct ExtractArgs {
    /// Path to the stego file (omit for `--amnesia`).
    #[arg(long)]
    pub input: PathBuf,
    /// Output path for the extracted payload.
    #[arg(long)]
    pub output: PathBuf,
    /// Steganographic technique.
    #[arg(long, value_enum)]
    pub technique: Technique,
    /// Key path for deniable extraction.
    #[arg(long)]
    pub key: Option<PathBuf>,
    /// Amnesiac mode: read from stdin, write to stdout.
    #[arg(long)]
    pub amnesia: bool,
}

/// Arguments for `embed-distributed`.
#[derive(Parser, Debug)]
pub struct EmbedDistributedArgs {
    /// Path to the payload file.
    #[arg(long)]
    pub input: PathBuf,
    /// Glob pattern matching cover files.
    #[arg(long)]
    pub covers: String,
    /// Number of data shards.
    #[arg(long, default_value = "3")]
    pub data_shards: u8,
    /// Number of parity shards.
    #[arg(long, default_value = "2")]
    pub parity_shards: u8,
    /// Output archive path.
    #[arg(long)]
    pub output_archive: PathBuf,
    /// Steganographic technique.
    #[arg(long, value_enum)]
    pub technique: Technique,
    /// Embedding profile.
    #[arg(long, value_enum, default_value = "standard")]
    pub profile: Profile,
    /// Target platform (when profile = survivable).
    #[arg(long, value_enum)]
    pub platform: Option<Platform>,
    /// Inject a canary shard.
    #[arg(long)]
    pub canary: bool,
    /// Geographic manifest TOML path.
    #[arg(long)]
    pub geo_manifest: Option<PathBuf>,
    /// Path to a 32-byte HMAC key for shard integrity. If omitted, a random
    /// key is generated and written next to the output archive.
    #[arg(long)]
    pub hmac_key: Option<PathBuf>,
}

/// Arguments for `extract-distributed`.
#[derive(Parser, Debug)]
pub struct ExtractDistributedArgs {
    /// Input archive or directory path.
    #[arg(long)]
    pub input_archive: PathBuf,
    /// Output path for the recovered payload.
    #[arg(long)]
    pub output: PathBuf,
    /// Steganographic technique.
    #[arg(long, value_enum)]
    pub technique: Technique,
    /// Number of data shards in the original distribution.
    #[arg(long, default_value = "3")]
    pub data_shards: u8,
    /// Number of parity shards in the original distribution.
    #[arg(long, default_value = "2")]
    pub parity_shards: u8,
    /// Path to the 32-byte HMAC key used during distribution.
    #[arg(long)]
    pub hmac_key: Option<PathBuf>,
}

/// Arguments for `analyse`.
#[derive(Parser, Debug)]
pub struct AnalyseArgs {
    /// Path to the cover file.
    #[arg(long)]
    pub cover: PathBuf,
    /// Steganographic technique.
    #[arg(long, value_enum)]
    pub technique: Technique,
    /// Output as JSON instead of a table.
    #[arg(long)]
    pub json: bool,
}

/// Arguments for `archive`.
#[derive(Parser, Debug)]
pub struct ArchiveArgs {
    /// Archive sub-operation.
    #[command(subcommand)]
    pub subcmd: ArchiveSubcommand,
}

/// Archive sub-operations.
#[derive(Subcommand, Debug)]
pub enum ArchiveSubcommand {
    /// Pack files into an archive.
    Pack {
        /// Files to include.
        #[arg(long, num_args = 1..)]
        files: Vec<PathBuf>,
        /// Archive format.
        #[arg(long, value_enum)]
        format: ArchiveFormat,
        /// Output archive path.
        #[arg(long)]
        output: PathBuf,
    },
    /// Unpack an archive.
    Unpack {
        /// Input archive path.
        #[arg(long)]
        input: PathBuf,
        /// Archive format.
        #[arg(long, value_enum)]
        format: ArchiveFormat,
        /// Output directory.
        #[arg(long)]
        output_dir: PathBuf,
    },
}

/// Arguments for `scrub`.
#[derive(Parser, Debug)]
pub struct ScrubArgs {
    /// Input text file.
    #[arg(long)]
    pub input: PathBuf,
    /// Output file.
    #[arg(long)]
    pub output: PathBuf,
    /// Target average sentence length.
    #[arg(long, default_value = "15")]
    pub avg_sentence_len: u32,
    /// Target vocabulary size.
    #[arg(long, default_value = "1000")]
    pub vocab_size: usize,
}

/// Arguments for `dead-drop`.
#[derive(Parser, Debug)]
pub struct DeadDropArgs {
    /// Cover image path.
    #[arg(long)]
    pub cover: PathBuf,
    /// Payload file path.
    #[arg(long)]
    pub input: PathBuf,
    /// Target platform.
    #[arg(long, value_enum)]
    pub platform: Platform,
    /// Output stego file.
    #[arg(long)]
    pub output: PathBuf,
    /// Steganographic technique.
    #[arg(long, value_enum, default_value = "lsb")]
    pub technique: Technique,
}

/// Arguments for `time-lock`.
#[derive(Parser, Debug)]
pub struct TimeLockArgs {
    /// Time-lock sub-operation.
    #[command(subcommand)]
    pub subcmd: TimeLockSubcommand,
}

/// Time-lock sub-operations.
#[derive(Subcommand, Debug)]
pub enum TimeLockSubcommand {
    /// Create a time-lock puzzle.
    Lock {
        /// Input payload file.
        #[arg(long)]
        input: PathBuf,
        /// Earliest unlock time (RFC 3339).
        #[arg(long)]
        unlock_at: String,
        /// Output puzzle file.
        #[arg(long)]
        output_puzzle: PathBuf,
    },
    /// Solve a time-lock puzzle (blocking).
    Unlock {
        /// Puzzle file.
        #[arg(long)]
        puzzle: PathBuf,
        /// Output payload file.
        #[arg(long)]
        output: PathBuf,
    },
    /// Non-blocking check on a puzzle.
    TryUnlock {
        /// Puzzle file.
        #[arg(long)]
        puzzle: PathBuf,
    },
}

/// Arguments for `watermark`.
#[derive(Parser, Debug)]
pub struct WatermarkArgs {
    /// Watermark sub-operation.
    #[command(subcommand)]
    pub subcmd: WatermarkSubcommand,
}

/// Watermark sub-operations.
#[derive(Subcommand, Debug)]
pub enum WatermarkSubcommand {
    /// Embed a forensic tripwire watermark.
    #[command(name = "embed-tripwire")]
    EmbedTripwire {
        /// Cover file path.
        #[arg(long)]
        cover: PathBuf,
        /// Output stego file.
        #[arg(long)]
        output: PathBuf,
        /// Recipient identifier.
        #[arg(long)]
        recipient_id: String,
    },
    /// Identify which recipient's watermark is present.
    Identify {
        /// Stego cover file.
        #[arg(long)]
        cover: PathBuf,
        /// Directory containing tag JSON files.
        #[arg(long)]
        tags: PathBuf,
    },
}

/// Arguments for `corpus`.
#[derive(Parser, Debug)]
pub struct CorpusArgs {
    /// Corpus sub-operation.
    #[command(subcommand)]
    pub subcmd: CorpusSubcommand,
}

/// Corpus sub-operations.
#[derive(Subcommand, Debug)]
pub enum CorpusSubcommand {
    /// Build a corpus index from a directory.
    Build {
        /// Directory to index.
        #[arg(long)]
        dir: PathBuf,
    },
    /// Search the corpus for matching covers.
    Search {
        /// Payload file.
        #[arg(long)]
        input: PathBuf,
        /// Steganographic technique.
        #[arg(long, value_enum)]
        technique: Technique,
        /// Maximum results to return.
        #[arg(long, default_value = "5")]
        top: usize,
        /// Restrict search to covers matching this AI model ID (e.g. "gemini").
        #[arg(long)]
        model: Option<String>,
        /// Cover resolution to match when `--model` is set, in `WIDTHxHEIGHT`
        /// format (e.g. "1024x1024").  Ignored if `--model` is absent.
        #[arg(long)]
        resolution: Option<String>,
    },
}

/// Arguments for (hidden) `panic`.
#[derive(Parser, Debug)]
pub struct PanicArgs {
    /// Key-material file paths to wipe.
    #[arg(long, num_args = 0..)]
    pub key_paths: Vec<String>,
}

/// Arguments for `completions`.
#[derive(Parser, Debug)]
pub struct CompletionsArgs {
    /// Shell to generate completions for (bash, zsh, fish, elvish, powershell).
    #[arg(value_enum)]
    pub shell: Shell,

    /// Write completions to a file instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

/// Arguments for `cipher`.
#[derive(Parser, Debug)]
pub struct CipherArgs {
    /// Cipher sub-operation.
    #[command(subcommand)]
    pub subcmd: CipherSubcommand,
}

/// Cipher sub-operations.
#[derive(Subcommand, Debug)]
pub enum CipherSubcommand {
    /// Encrypt a file with AES-256-GCM. A random 12-byte nonce is generated and
    /// prepended to the output ciphertext.
    Encrypt {
        /// Input plaintext file.
        #[arg(long)]
        input: PathBuf,
        /// 32-byte key file.
        #[arg(long)]
        key: PathBuf,
        /// Output file (nonce ‖ ciphertext).
        #[arg(long)]
        output: PathBuf,
    },
    /// Decrypt a file encrypted with AES-256-GCM. The nonce is read from the
    /// first 12 bytes of the input file.
    Decrypt {
        /// Input ciphertext file (12-byte nonce in first bytes).
        #[arg(long)]
        input: PathBuf,
        /// 32-byte key file.
        #[arg(long)]
        key: PathBuf,
        /// Output plaintext file.
        #[arg(long)]
        output: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parse_version() {
        let cli = Cli::try_parse_from(["shadowforge", "version"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn cli_parse_keygen() {
        let cli = Cli::try_parse_from([
            "shadowforge",
            "keygen",
            "--algorithm",
            "kyber1024",
            "--output",
            "/tmp/keys",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn cli_parse_keygen_sign() {
        let cli = Cli::try_parse_from([
            "shadowforge",
            "keygen",
            "sign",
            "--input",
            "payload.bin",
            "--secret-key",
            "secret.key",
            "--output",
            "payload.sig",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn cli_parse_keygen_verify() {
        let cli = Cli::try_parse_from([
            "shadowforge",
            "keygen",
            "verify",
            "--input",
            "payload.bin",
            "--public-key",
            "public.key",
            "--signature",
            "payload.sig",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn cli_parse_embed() {
        let cli = Cli::try_parse_from([
            "shadowforge",
            "embed",
            "--input",
            "payload.bin",
            "--cover",
            "cover.png",
            "--output",
            "stego.png",
            "--technique",
            "lsb",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn cli_parse_extract() {
        let cli = Cli::try_parse_from([
            "shadowforge",
            "extract",
            "--input",
            "stego.png",
            "--output",
            "payload.bin",
            "--technique",
            "lsb",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn cli_parse_analyse_json() {
        let cli = Cli::try_parse_from([
            "shadowforge",
            "analyse",
            "--cover",
            "cover.png",
            "--technique",
            "lsb",
            "--json",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn cli_parse_scrub() {
        let cli = Cli::try_parse_from([
            "shadowforge",
            "scrub",
            "--input",
            "text.txt",
            "--output",
            "clean.txt",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn cli_parse_time_lock_lock() {
        let cli = Cli::try_parse_from([
            "shadowforge",
            "time-lock",
            "lock",
            "--input",
            "secret.bin",
            "--unlock-at",
            "2025-12-31T00:00:00Z",
            "--output-puzzle",
            "puzzle.json",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn cli_parse_completions() {
        let cli = Cli::try_parse_from(["shadowforge", "completions", "bash"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn cli_parse_embed_distributed() {
        let cli = Cli::try_parse_from([
            "shadowforge",
            "embed-distributed",
            "--input",
            "payload.bin",
            "--covers",
            "covers/*.png",
            "--output-archive",
            "dist.zip",
            "--technique",
            "lsb",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn cli_panic_hidden() {
        // Panic command should not appear in help but should parse
        let cli = Cli::try_parse_from(["shadowforge", "panic"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn version_output_contains_semver() {
        let version = env!("CARGO_PKG_VERSION");
        assert!(version.contains('.'), "version should be semver");
    }

    #[test]
    fn cli_parse_cipher_encrypt() {
        let cli = Cli::try_parse_from([
            "shadowforge",
            "cipher",
            "encrypt",
            "--input",
            "payload.bin",
            "--key",
            "key.bin",
            "--output",
            "out.enc",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn cli_parse_cipher_decrypt() {
        let cli = Cli::try_parse_from([
            "shadowforge",
            "cipher",
            "decrypt",
            "--input",
            "out.enc",
            "--key",
            "key.bin",
            "--output",
            "recovered.bin",
        ]);
        assert!(cli.is_ok());
    }
}

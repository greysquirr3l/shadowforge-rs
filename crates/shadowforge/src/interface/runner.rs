//! CLI runner — dispatches parsed commands to application services.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Maximum payload size accepted from stdin (256 MiB).
const MAX_STDIN_PAYLOAD: u64 = 256 * 1024 * 1024;

use clap::Parser;

use crate::application::services::{
    AnalyseService, AppError, ArchiveService, CipherService, CorpusService, EmbedService,
    ExtractService, KeyGenService, ScrubService,
};
use crate::domain::errors::{CanaryError, OpsecError, StegoError};
use crate::domain::ports::{EmbedTechnique, ExtractTechnique, MediaLoader};
use crate::domain::types::{CoverMedia, CoverMediaKind, Payload, Signature, StegoTechnique};

use super::cli::{self, Cli, Commands};

/// Run the CLI. Returns `Ok(())` on success.
///
/// Unknown subcommands and invalid arguments are handled by clap: it prints a
/// formatted error with suggestions and exits with code 2.  Using
/// [`Cli::try_parse`] here makes that handoff explicit rather than relying on
/// the implicit `process::exit` inside [`Cli::parse`].
///
/// # Errors
/// Returns [`AppError`] on any service failure.
pub fn run() -> Result<(), AppError> {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => e.exit(), // prints clap-formatted message, exits with code 2
    };
    dispatch(cli)
}

/// Dispatch a parsed CLI to the appropriate handler.
///
/// # Errors
/// Returns [`AppError`] on any service failure.
pub fn dispatch(cli: Cli) -> Result<(), AppError> {
    match cli.command {
        Commands::Version => {
            print_version();
            Ok(())
        }
        Commands::Keygen(args) => cmd_keygen(&args),
        Commands::Embed(args) => cmd_embed(&args),
        Commands::Extract(args) => cmd_extract(&args),
        Commands::EmbedDistributed(args) => cmd_embed_distributed(&args),
        Commands::ExtractDistributed(args) => cmd_extract_distributed(&args),
        Commands::Analyse(args) => cmd_analyse(&args),
        Commands::Archive(args) => cmd_archive(&args),
        Commands::Scrub(args) => cmd_scrub(&args),
        Commands::DeadDrop(args) => cmd_dead_drop(&args),
        Commands::TimeLock(args) => cmd_time_lock(&args),
        Commands::Watermark(args) => cmd_watermark(&args),
        Commands::Corpus(args) => cmd_corpus(&args),
        Commands::Panic(args) => cmd_panic(&args),
        Commands::Completions(args) => cmd_completions(&args),
        Commands::Cipher(args) => cmd_cipher(&args),
    }
}

fn print_version() {
    let version = env!("CARGO_PKG_VERSION");
    let sha = option_env!("VERGEN_GIT_SHA").unwrap_or("unknown");
    println!("shadowforge {version} ({sha})");
}

// ─── Keygen ───────────────────────────────────────────────────────────────────

fn cmd_keygen(args: &cli::KeygenArgs) -> Result<(), AppError> {
    match &args.subcmd {
        Some(cli::KeygenSubcommand::Sign {
            input,
            secret_key,
            output,
        }) => cmd_keygen_sign(input, secret_key, output),
        Some(cli::KeygenSubcommand::Verify {
            input,
            public_key,
            signature,
        }) => cmd_keygen_verify(input, public_key, signature),
        None => cmd_keygen_generate(args),
    }
}

fn cmd_keygen_generate(args: &cli::KeygenArgs) -> Result<(), AppError> {
    let Some(dir) = args.output.as_ref() else {
        return Err(AppError::Stego(StegoError::MalformedCoverData {
            reason: "--output is required when no keygen subcommand is used".to_string(),
        }));
    };
    let Some(algorithm) = args.algorithm else {
        return Err(AppError::Stego(StegoError::MalformedCoverData {
            reason: "--algorithm is required when no keygen subcommand is used".to_string(),
        }));
    };

    fs_create_dir_all(dir)?;

    match algorithm {
        cli::Algorithm::Kyber1024 => {
            let enc = crate::adapters::crypto::MlKemEncryptor;
            let kp = KeyGenService::generate_keypair(&enc)?;
            fs_write(&dir.join("public.key"), kp.public_key.as_ref())?;
            fs_write(&dir.join("secret.key"), kp.secret_key.as_ref())?;
        }
        cli::Algorithm::Dilithium3 => {
            let signer = crate::adapters::crypto::MlDsaSigner;
            let kp = KeyGenService::generate_signing_keypair(&signer)?;
            fs_write(&dir.join("public.key"), kp.public_key.as_ref())?;
            fs_write(&dir.join("secret.key"), kp.secret_key.as_ref())?;
        }
    }
    eprintln!("Keys written to {}", dir.display());
    Ok(())
}

fn cmd_keygen_sign(input: &Path, secret_key: &Path, output: &Path) -> Result<(), AppError> {
    let signer = crate::adapters::crypto::MlDsaSigner;
    let message = fs_read(input)?;
    let sk = fs_read(secret_key)?;
    let signature = KeyGenService::sign(&signer, &sk, &message)?;
    fs_write(output, signature.0.as_ref())?;
    eprintln!("Signature written to {}", output.display());
    Ok(())
}

fn cmd_keygen_verify(input: &Path, public_key: &Path, signature: &Path) -> Result<(), AppError> {
    let signer = crate::adapters::crypto::MlDsaSigner;
    let message = fs_read(input)?;
    let pk = fs_read(public_key)?;
    let sig = Signature(bytes::Bytes::from(fs_read(signature)?));
    let valid = KeyGenService::verify(&signer, &pk, &message, &sig)?;
    if valid {
        eprintln!("Signature verification: ok");
        Ok(())
    } else {
        Err(AppError::Crypto(
            crate::domain::errors::CryptoError::VerificationFailed {
                reason: "invalid signature".to_string(),
            },
        ))
    }
}

// ─── Embed ────────────────────────────────────────────────────────────────────

fn cmd_embed(args: &cli::EmbedArgs) -> Result<(), AppError> {
    let technique = resolve_technique(args.technique);
    let embedder = build_embedder(technique);

    let payload_bytes = fs_read(&args.input)?;
    let mut payload = Payload::from_bytes(payload_bytes);

    if args.scrub_style {
        let scrubber = crate::adapters::scrubber::StyloScrubberImpl::new();
        let profile = crate::domain::types::StyloProfile {
            normalize_punctuation: true,
            target_avg_sentence_len: 15.0,
            target_vocab_size: 1000,
        };
        let text = String::from_utf8_lossy(payload.as_bytes());
        let result = ScrubService::scrub(&text, &profile, &scrubber)?;
        payload = Payload::from_bytes(result.into_bytes());
    }

    if args.amnesia {
        let pipeline = crate::adapters::opsec::AmnesiaPipelineImpl::new();
        let mut payload_cursor = io::Cursor::new(payload.as_bytes().to_vec());
        let mut cover_input = io::stdin().lock();
        let mut output = io::stdout().lock();
        crate::application::services::AmnesiaPipelineService::embed_in_memory(
            &mut payload_cursor,
            &mut cover_input,
            &mut output,
            embedder.as_ref(),
            &pipeline,
        )?;
    } else if args.deniable {
        let cover_path = args.cover.as_ref().ok_or_else(|| {
            crate::domain::errors::DeniableError::EmbedFailed {
                reason: "--cover is required for deniable embedding".into(),
            }
        })?;
        let cover = load_cover_from_path(cover_path, technique)?;

        let decoy_path = args.decoy_payload.as_ref().ok_or_else(|| {
            crate::domain::errors::DeniableError::EmbedFailed {
                reason: "--decoy-payload is required for deniable embedding".into(),
            }
        })?;
        let decoy_bytes = fs_read(decoy_path)?;
        let primary_key = match &args.key {
            Some(p) => fs_read(p)?,
            None => vec![0u8; 32],
        };
        let decoy_key = match &args.decoy_key {
            Some(p) => fs_read(p)?,
            None => vec![1u8; 32],
        };
        let pair = crate::domain::types::DeniablePayloadPair {
            real_payload: payload.as_bytes().to_vec(),
            decoy_payload: decoy_bytes,
        };
        let keys = crate::domain::types::DeniableKeySet {
            primary_key,
            decoy_key,
        };
        let deniable = crate::adapters::stego::DualPayloadEmbedder;
        let stego = crate::application::services::DeniableEmbedService::embed_dual(
            cover,
            &pair,
            &keys,
            embedder.as_ref(),
            &deniable,
        )?;
        save_cover_to_path(&stego, &args.output)?;
        eprintln!("Deniable embedding complete");
    } else {
        // Note: profile and platform only apply to distributed embedding.
        // Single-cover embedding uses the technique directly without profile constraints.
        if matches!(args.profile, cli::Profile::Standard) {
            // Standard profile: silent
        } else {
            eprintln!(
                "Note: --profile {:?} only applies to distributed embedding; \
                 single-cover uses technique directly",
                args.profile
            );
        }

        let cover_path = args.cover.as_ref().ok_or_else(|| {
            crate::domain::errors::StegoError::MalformedCoverData {
                reason: "--cover is required when not using --amnesia".into(),
            }
        })?;
        let cover = load_cover_from_path(cover_path, technique)?;
        let stego = EmbedService::embed(cover, &payload, embedder.as_ref())?;
        save_cover_to_path(&stego, &args.output)?;
        eprintln!("Embedded {} bytes", payload.len());
    }
    Ok(())
}

// ─── Extract ──────────────────────────────────────────────────────────────────

fn cmd_extract(args: &cli::ExtractArgs) -> Result<(), AppError> {
    let technique = resolve_technique(args.technique);
    let extractor = build_extractor(technique);
    let deniable_key = match &args.key {
        Some(path) => Some(fs_read(path)?),
        None => None,
    };

    if args.amnesia {
        let mut buf = Vec::new();
        io::stdin()
            .lock()
            .take(MAX_STDIN_PAYLOAD)
            .read_to_end(&mut buf)
            .map_err(|e| crate::domain::errors::StegoError::MalformedCoverData {
                reason: format!("stdin read: {e}"),
            })?;
        let cover = load_cover(technique, &buf);
        let payload = if let Some(key) = deniable_key.as_deref() {
            let deniable = crate::adapters::stego::DualPayloadEmbedder;
            crate::application::services::DeniableEmbedService::extract_with_key(
                &cover,
                key,
                extractor.as_ref(),
                &deniable,
            )?
        } else {
            ExtractService::extract(&cover, extractor.as_ref())?
        };
        io::stdout().write_all(payload.as_bytes()).map_err(|e| {
            crate::domain::errors::StegoError::MalformedCoverData {
                reason: format!("stdout write: {e}"),
            }
        })?;
    } else {
        let stego = load_cover_from_path(&args.input, technique)?;
        let payload = if let Some(key) = deniable_key.as_deref() {
            let deniable = crate::adapters::stego::DualPayloadEmbedder;
            crate::application::services::DeniableEmbedService::extract_with_key(
                &stego,
                key,
                extractor.as_ref(),
                &deniable,
            )?
        } else {
            ExtractService::extract(&stego, extractor.as_ref())?
        };
        fs_write(&args.output, payload.as_bytes())?;
        eprintln!("Extracted {} bytes", payload.len());
    }
    Ok(())
}

// ─── Embed-distributed ────────────────────────────────────────────────────────

fn cmd_embed_distributed(args: &cli::EmbedDistributedArgs) -> Result<(), AppError> {
    let technique = resolve_technique(args.technique);
    let embedder = build_embedder(technique);

    let payload_bytes = fs_read(&args.input)?;
    let payload = Payload::from_bytes(payload_bytes);

    let cover_paths = collect_cover_paths(&args.covers)?;
    let covers: Result<Vec<CoverMedia>, AppError> = cover_paths
        .iter()
        .map(|path| load_cover_from_path(path, technique))
        .collect();
    let covers = covers?;

    let profile = resolve_profile(args.profile, args.platform);
    let (mut stego_covers, generated_hmac_key) =
        distribute_covers(args, &payload, covers, &profile, embedder.as_ref())?;

    // Embed canary shard if requested
    let canary_metadata = if args.canary {
        let canary_impl = crate::adapters::canary::CanaryServiceImpl::new(64, 5);
        let (covers_with_canary, shard) =
            crate::application::services::CanaryShardService::embed_canary(
                stego_covers,
                embedder.as_ref(),
                &canary_impl,
            )?;
        stego_covers = covers_with_canary;
        Some(shard)
    } else {
        None
    };

    let files: Vec<(String, Vec<u8>)> = stego_covers
        .iter()
        .enumerate()
        .map(|(i, cover)| {
            Ok((
                format!("shard_{i:04}.{}", cover_file_extension(cover.kind)),
                serialise_cover_to_bytes(cover)?,
            ))
        })
        .collect::<Result<_, AppError>>()?;
    let file_refs: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    let handler = crate::adapters::archive::ArchiveHandlerImpl::new();
    let archive = ArchiveService::pack(
        &file_refs,
        crate::domain::types::ArchiveFormat::Zip,
        &handler,
    )?;
    fs_write(&args.output_archive, &archive)?;

    // Persist HMAC key so extract-distributed can use it
    if let Some(hmac_key) = generated_hmac_key {
        let key_path = args.output_archive.with_extension("hmac");
        fs_write(&key_path, &hmac_key)?;
        eprintln!("HMAC key written to {}", key_path.display());
    }

    // Persist canary metadata if embedded
    if let Some(canary_shard) = canary_metadata {
        let canary_path = args.output_archive.with_extension("canary");
        let canary_json = serde_json::to_string_pretty(&canary_shard).map_err(|e| {
            let stego_err = StegoError::MalformedCoverData {
                reason: format!("Failed to serialize canary metadata: {e}"),
            };
            AppError::Canary(CanaryError::EmbedFailed { source: stego_err })
        })?;
        fs_write(&canary_path, canary_json.as_bytes())?;
        eprintln!("Canary metadata written to {}", canary_path.display());
    }

    eprintln!(
        "Distributed into {} shards → {}",
        stego_covers.len(),
        args.output_archive.display()
    );
    Ok(())
}

fn distribute_covers(
    args: &cli::EmbedDistributedArgs,
    payload: &Payload,
    covers: Vec<CoverMedia>,
    profile: &crate::domain::types::EmbeddingProfile,
    embedder: &dyn EmbedTechnique,
) -> Result<(Vec<CoverMedia>, Option<Vec<u8>>), AppError> {
    if let Some(manifest_path) = &args.geo_manifest {
        let manifest = load_geographic_manifest(manifest_path)?;
        let geo_distributor = crate::adapters::opsec::GeographicDistributorImpl::new();
        let stego_covers =
            crate::application::services::DistributeService::distribute_with_geographic_manifest(
                payload,
                covers,
                &manifest,
                embedder,
                &geo_distributor,
            )?;
        return Ok((stego_covers, None));
    }

    let hmac_key = if let Some(p) = &args.hmac_key {
        fs_read(p)?
    } else {
        crate::adapters::distribution::DistributorImpl::generate_hmac_key()
    };
    let generated_hmac_key = if args.hmac_key.is_none() {
        Some(hmac_key.clone())
    } else {
        None
    };
    let corrector_for_dist: Box<dyn crate::domain::ports::ErrorCorrector> = Box::new(
        crate::adapters::correction::RsErrorCorrector::new(hmac_key.clone()),
    );
    let distributor = crate::adapters::distribution::DistributorImpl::new_with_shard_config(
        hmac_key,
        args.data_shards,
        args.parity_shards,
        corrector_for_dist,
    );
    let (matcher, optimiser, compressor) = crate::adapters::adaptive::build_adaptive_profile_deps();

    let stego_covers =
        crate::application::services::DistributeService::distribute_with_profile_hardening(
            payload,
            covers,
            profile,
            &distributor,
            embedder,
            &crate::application::services::AdaptiveProfileDeps {
                matcher: &matcher,
                optimiser: &optimiser,
                compressor: &compressor,
            },
        )?;
    Ok((stego_covers, generated_hmac_key))
}

fn load_geographic_manifest(
    manifest_path: &Path,
) -> Result<crate::domain::types::GeographicManifest, AppError> {
    let manifest_raw = fs_read(manifest_path)?;
    let manifest_str = String::from_utf8(manifest_raw).map_err(|e| OpsecError::ManifestError {
        reason: format!("manifest is not valid UTF-8: {e}"),
    })?;
    toml::from_str(&manifest_str).map_err(|e| {
        OpsecError::ManifestError {
            reason: format!("manifest parse failed: {e}"),
        }
        .into()
    })
}

// ─── Extract-distributed ──────────────────────────────────────────────────────

fn cmd_extract_distributed(args: &cli::ExtractDistributedArgs) -> Result<(), AppError> {
    let technique = resolve_technique(args.technique);
    let extractor = build_extractor(technique);

    let archive_bytes = fs_read(&args.input_archive)?;
    let handler = crate::adapters::archive::ArchiveHandlerImpl::new();
    let entries = ArchiveService::unpack(
        &archive_bytes,
        crate::domain::types::ArchiveFormat::Zip,
        &handler,
    )?;

    let covers: Vec<CoverMedia> = entries
        .iter()
        .map(|(name, data)| load_cover_from_named_bytes(name, technique, data))
        .collect::<Result<_, AppError>>()?;

    let hmac_key = if let Some(p) = &args.hmac_key {
        fs_read(p)?
    } else {
        // Try the default location next to the archive
        let default_path = args.input_archive.with_extension("hmac");
        fs_read(&default_path)?
    };
    let corrector_for_recon: Box<dyn crate::domain::ports::ErrorCorrector> =
        Box::new(crate::adapters::correction::RsErrorCorrector::new(hmac_key));
    let reconstructor = crate::adapters::reconstruction::ReconstructorImpl::new(
        args.data_shards,
        args.parity_shards,
        0,
        corrector_for_recon,
    );
    let payload = crate::application::services::ReconstructService::reconstruct(
        covers,
        extractor.as_ref(),
        &reconstructor,
        &|done, total| eprintln!("Reconstructing: {done}/{total}"),
    )?;
    fs_write(&args.output, payload.as_bytes())?;
    eprintln!("Reconstructed {} bytes", payload.len());
    Ok(())
}

// ─── Analyse ──────────────────────────────────────────────────────────────────

/// Format an `AnalysisReport` as a human-readable string.
/// Exposed for unit testing.
pub(crate) fn format_analysis_report(report: &crate::domain::types::AnalysisReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "Technique:     {:?}", report.technique);
    let _ = writeln!(out, "Capacity:      {} bytes", report.cover_capacity.bytes);
    let _ = writeln!(out, "Chi-square:    {:.2} dB", report.chi_square_score);
    let _ = writeln!(out, "Risk:          {:?}", report.detectability_risk);
    let _ = writeln!(
        out,
        "Recommended:   {} bytes",
        report.recommended_max_payload_bytes
    );
    if let Some(ai) = &report.ai_watermark {
        let _ = writeln!(out, "--- AI Watermark Detection ---");
        let _ = writeln!(
            out,
            "  Detected:             {}",
            if ai.detected { "yes" } else { "no" }
        );
        if let Some(model_id) = &ai.model_id {
            let _ = writeln!(out, "  Model:                {model_id}");
        }
        if ai.total_strong_bins > 0 {
            let _ = writeln!(out, "  Confidence:           {:.4}", ai.confidence);
            let _ = writeln!(
                out,
                "  Matched strong bins:  {}/{}",
                ai.matched_strong_bins, ai.total_strong_bins
            );
        } else {
            let _ = writeln!(out, "  Status:               no known profile match");
        }
    }
    if let Some(s) = &report.spectral_score {
        let _ = writeln!(out, "--- Spectral Detectability ---");
        let _ = writeln!(out, "  Phase coherence drop: {:.4}", s.phase_coherence_drop);
        let _ = writeln!(
            out,
            "  Carrier SNR drop:     {:.2} dB",
            s.carrier_snr_drop_db
        );
        let _ = writeln!(
            out,
            "  Sample-pair asymmetry:{:.4}",
            s.sample_pair_asymmetry
        );
        let _ = writeln!(out, "  Spectral risk:        {:?}", s.combined_risk);
    }
    out
}

fn cmd_analyse(args: &cli::AnalyseArgs) -> Result<(), AppError> {
    let technique = resolve_technique(args.technique);
    let cover = load_cover_from_path(&args.cover, technique)?;
    let analyser = crate::adapters::analysis::CapacityAnalyserImpl::new();
    let report = AnalyseService::analyse(&cover, technique, &analyser)?;

    if args.json {
        let json = serde_json::to_string_pretty(&report).map_err(|e| {
            crate::domain::errors::AnalysisError::ComputationFailed {
                reason: format!("json serialisation: {e}"),
            }
        })?;
        println!("{json}");
    } else {
        print!("{}", format_analysis_report(&report));
    }
    Ok(())
}

// ─── Archive ──────────────────────────────────────────────────────────────────

fn cmd_archive(args: &cli::ArchiveArgs) -> Result<(), AppError> {
    match &args.subcmd {
        cli::ArchiveSubcommand::Pack {
            files,
            format,
            output,
        } => {
            let file_data: Result<Vec<(String, Vec<u8>)>, AppError> = files
                .iter()
                .map(|p| {
                    let name = p.file_name().map_or_else(
                        || p.display().to_string(),
                        |n| n.to_string_lossy().into_owned(),
                    );
                    let data = fs_read(p)?;
                    Ok((name, data))
                })
                .collect();
            let file_data = file_data?;
            let refs: Vec<(&str, &[u8])> = file_data
                .iter()
                .map(|(n, d)| (n.as_str(), d.as_slice()))
                .collect();
            let handler = crate::adapters::archive::ArchiveHandlerImpl::new();
            let fmt = resolve_archive_format(*format);
            let packed = ArchiveService::pack(&refs, fmt, &handler)?;
            fs_write(output, &packed)?;
            eprintln!("Packed {} files → {}", files.len(), output.display());
        }
        cli::ArchiveSubcommand::Unpack {
            input,
            format,
            output_dir,
        } => {
            let data = fs_read(input)?;
            let handler = crate::adapters::archive::ArchiveHandlerImpl::new();
            let fmt = resolve_archive_format(*format);
            let entries = ArchiveService::unpack(&data, fmt, &handler)?;
            fs_create_dir_all(output_dir)?;
            for (name, content) in &entries {
                let path = output_dir.join(name);
                if let Some(parent) = path.parent() {
                    fs_create_dir_all(parent)?;
                }
                fs_write(&path, content.as_ref())?;
            }
            eprintln!(
                "Unpacked {} entries → {}",
                entries.len(),
                output_dir.display()
            );
        }
    }
    Ok(())
}

// ─── Scrub ────────────────────────────────────────────────────────────────────

fn cmd_scrub(args: &cli::ScrubArgs) -> Result<(), AppError> {
    let text = std::fs::read_to_string(&args.input).map_err(|e| {
        crate::domain::errors::ScrubberError::InvalidUtf8 {
            reason: format!("read: {e}"),
        }
    })?;
    let scrubber = crate::adapters::scrubber::StyloScrubberImpl::new();
    let profile = crate::domain::types::StyloProfile {
        normalize_punctuation: true,
        target_avg_sentence_len: f64::from(args.avg_sentence_len),
        target_vocab_size: args.vocab_size,
    };
    let result = ScrubService::scrub(&text, &profile, &scrubber)?;
    fs_write(&args.output, result.as_bytes())?;
    eprintln!("Scrubbed text → {}", args.output.display());
    Ok(())
}

// ─── Dead Drop ────────────────────────────────────────────────────────────────

fn cmd_dead_drop(args: &cli::DeadDropArgs) -> Result<(), AppError> {
    let technique = resolve_technique(args.technique);
    let embedder = build_embedder(technique);
    let cover = load_cover_from_path(&args.cover, technique)?;
    let payload_bytes = fs_read(&args.input)?;
    let payload = Payload::from_bytes(payload_bytes);
    let platform = resolve_platform(args.platform);
    let encoder = crate::adapters::deadrop::DeadDropEncoderImpl::new();
    let stego = crate::application::services::DeadDropService::encode(
        cover,
        &payload,
        &platform,
        embedder.as_ref(),
        &encoder,
    )?;
    save_cover_to_path(&stego, &args.output)?;
    eprintln!("Dead drop encoded for {platform:?}");
    Ok(())
}

// ─── Time Lock ────────────────────────────────────────────────────────────────

fn cmd_time_lock(args: &cli::TimeLockArgs) -> Result<(), AppError> {
    let service = crate::adapters::timelock::TimeLockServiceImpl::default();
    match &args.subcmd {
        cli::TimeLockSubcommand::Lock {
            input,
            unlock_at,
            output_puzzle,
        } => {
            let data = fs_read(input)?;
            let payload = Payload::from_bytes(data);
            let ts = chrono::DateTime::parse_from_rfc3339(unlock_at)
                .map_err(
                    |e| crate::domain::errors::TimeLockError::ComputationFailed {
                        reason: format!("invalid RFC 3339 timestamp: {e}"),
                    },
                )?
                .with_timezone(&chrono::Utc);
            let puzzle =
                crate::application::services::TimeLockServiceApp::lock(&payload, ts, &service)?;
            let encoded = serde_json::to_vec_pretty(&puzzle).map_err(|e| {
                crate::domain::errors::TimeLockError::ComputationFailed {
                    reason: format!("serialize puzzle: {e}"),
                }
            })?;
            fs_write(output_puzzle, &encoded)?;
            eprintln!("Puzzle → {}", output_puzzle.display());
        }
        cli::TimeLockSubcommand::Unlock {
            puzzle: puzzle_path,
            output,
        } => {
            let data = fs_read(puzzle_path)?;
            let puzzle: crate::domain::types::TimeLockPuzzle = serde_json::from_slice(&data)
                .map_err(
                    |e| crate::domain::errors::TimeLockError::ComputationFailed {
                        reason: format!("deserialize puzzle: {e}"),
                    },
                )?;
            let payload =
                crate::application::services::TimeLockServiceApp::unlock(&puzzle, &service)?;
            fs_write(output, payload.as_bytes())?;
            eprintln!("Unlocked {} bytes", payload.len());
        }
        cli::TimeLockSubcommand::TryUnlock {
            puzzle: puzzle_path,
        } => {
            let data = fs_read(puzzle_path)?;
            let puzzle: crate::domain::types::TimeLockPuzzle = serde_json::from_slice(&data)
                .map_err(
                    |e| crate::domain::errors::TimeLockError::ComputationFailed {
                        reason: format!("deserialize puzzle: {e}"),
                    },
                )?;
            match crate::application::services::TimeLockServiceApp::try_unlock(&puzzle, &service)? {
                Some(p) => eprintln!("Puzzle solved: {} bytes", p.len()),
                None => eprintln!("Puzzle not yet solvable"),
            }
        }
    }
    Ok(())
}

// ─── Watermark ────────────────────────────────────────────────────────────────

fn cmd_watermark(args: &cli::WatermarkArgs) -> Result<(), AppError> {
    match &args.subcmd {
        cli::WatermarkSubcommand::EmbedTripwire {
            cover,
            output,
            recipient_id,
        } => {
            let cover_media =
                load_cover_from_path(cover, crate::domain::types::StegoTechnique::LsbImage)?;
            let watermarker = crate::adapters::opsec::ForensicWatermarkerImpl::new();
            let rid = uuid::Uuid::parse_str(recipient_id).map_err(|e| {
                crate::domain::errors::OpsecError::WatermarkError {
                    reason: format!("invalid UUID: {e}"),
                }
            })?;
            let tag = crate::domain::types::WatermarkTripwireTag {
                recipient_id: rid,
                embedding_seed: recipient_id.as_bytes().to_vec(),
            };
            let stego = crate::application::services::ForensicService::embed_tripwire(
                cover_media,
                &tag,
                &watermarker,
            )?;
            save_cover_to_path(&stego, output)?;
            eprintln!("Tripwire embedded for {recipient_id}");
        }
        cli::WatermarkSubcommand::Identify { cover, tags } => {
            let cover_media =
                load_cover_from_path(cover, crate::domain::types::StegoTechnique::LsbImage)?;
            let watermarker = crate::adapters::opsec::ForensicWatermarkerImpl::new();
            let tag_list = load_watermark_tags(tags)?;
            let receipt = crate::application::services::ForensicService::identify_recipient(
                &cover_media,
                &tag_list,
                &watermarker,
            )?;
            match receipt {
                Some(r) => println!("Identified recipient: {r}"),
                None => println!("No matching watermark found"),
            }
        }
    }
    Ok(())
}

// ─── Corpus ───────────────────────────────────────────────────────────────────

fn cmd_corpus(args: &cli::CorpusArgs) -> Result<(), AppError> {
    let index = crate::adapters::corpus::CorpusIndexImpl::new();
    match &args.subcmd {
        cli::CorpusSubcommand::Build { dir } => {
            let count = CorpusService::build_index(&index, dir)?;
            eprintln!("Indexed {count} images from {}", dir.display());
        }
        cli::CorpusSubcommand::Search {
            input,
            technique,
            top,
            model,
            resolution,
        } => {
            let data = fs_read(input)?;
            let payload = Payload::from_bytes(data);
            let tech = resolve_technique(*technique);

            // If --model is provided, use model-aware search.  --resolution
            // is required in that case; an absent or unparseable value returns
            // a clear error rather than silently falling back to (0, 0).
            let results = if let Some(model_id) = model {
                let res = resolution
                    .as_deref()
                    .and_then(|s| {
                        let mut parts = s.splitn(2, 'x');
                        let w = parts.next()?.parse::<u32>().ok()?;
                        let h = parts.next()?.parse::<u32>().ok()?;
                        Some((w, h))
                    })
                    .ok_or_else(|| {
                        AppError::Stego(StegoError::MalformedCoverData {
                            reason: "--model requires --resolution in WIDTHxHEIGHT format \
                                     (e.g. --resolution 1024x1024)"
                                .to_string(),
                        })
                    })?;
                CorpusService::search_for_model(&index, &payload, model_id, res, *top)?
            } else {
                CorpusService::search(&index, &payload, tech, *top)?
            };

            for entry in &results {
                println!("{}", entry.path);
            }
        }
    }
    Ok(())
}

// ─── Panic ────────────────────────────────────────────────────────────────────

fn cmd_panic(args: &cli::PanicArgs) -> Result<(), AppError> {
    let config = crate::domain::types::PanicWipeConfig {
        key_paths: args.key_paths.iter().map(PathBuf::from).collect(),
        config_paths: Vec::new(),
        temp_dirs: Vec::new(),
    };
    let wiper = crate::adapters::opsec::SecurePanicWiper::new();
    crate::application::services::PanicWipeService::wipe(&config, &wiper)?;
    Ok(())
}

// ─── Completions ──────────────────────────────────────────────────────────────

fn cmd_completions(args: &cli::CompletionsArgs) -> Result<(), AppError> {
    use clap::CommandFactory;
    use clap_complete::generate;

    let mut cmd = Cli::command();
    match &args.output {
        Some(path) => {
            let mut file = std::fs::File::create(path).map_err(|e| {
                AppError::Stego(crate::domain::errors::StegoError::MalformedCoverData {
                    reason: format!("write {}: {e}", path.display()),
                })
            })?;
            generate(args.shell, &mut cmd, "shadowforge", &mut file);
        }
        None => {
            generate(args.shell, &mut cmd, "shadowforge", &mut io::stdout());
        }
    }
    Ok(())
}

// ─── Cipher ───────────────────────────────────────────────────────────────────

/// AES-256-GCM nonce length in bytes.
const AES_GCM_NONCE_LEN: usize = 12;

fn cmd_cipher(args: &cli::CipherArgs) -> Result<(), AppError> {
    use rand_core::Rng as _;

    let cipher = crate::adapters::crypto::Aes256GcmCipher;
    match &args.subcmd {
        cli::CipherSubcommand::Encrypt { input, key, output } => {
            let plaintext = fs_read(input)?;
            let key_bytes = fs_read(key)?;
            let mut nonce = [0u8; AES_GCM_NONCE_LEN];
            rand::rng().fill_bytes(&mut nonce);
            let ciphertext = CipherService::encrypt(&cipher, &key_bytes, &nonce, &plaintext)?;
            let mut out = Vec::with_capacity(AES_GCM_NONCE_LEN.strict_add(ciphertext.len()));
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ciphertext);
            fs_write(output, &out)?;
            eprintln!(
                "Encrypted {} bytes -> {}",
                plaintext.len(),
                output.display()
            );
        }
        cli::CipherSubcommand::Decrypt { input, key, output } => {
            let data = fs_read(input)?;
            let key_bytes = fs_read(key)?;
            if data.len() < AES_GCM_NONCE_LEN {
                return Err(AppError::Crypto(
                    crate::domain::errors::CryptoError::InvalidNonceLength {
                        expected: AES_GCM_NONCE_LEN,
                        got: data.len(),
                    },
                ));
            }
            let (nonce, ciphertext) = data.split_at(AES_GCM_NONCE_LEN);
            let plaintext = CipherService::decrypt(&cipher, &key_bytes, nonce, ciphertext)?;
            fs_write(output, &plaintext)?;
            eprintln!(
                "Decrypted {} bytes -> {}",
                plaintext.len(),
                output.display()
            );
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn fs_read(path: &Path) -> Result<Vec<u8>, AppError> {
    std::fs::read(path).map_err(|e| {
        AppError::Stego(crate::domain::errors::StegoError::MalformedCoverData {
            reason: format!("read {}: {e}", path.display()),
        })
    })
}

fn fs_write(path: &Path, data: &[u8]) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        fs_create_dir_all(parent)?;
    }
    std::fs::write(path, data).map_err(|e| {
        AppError::Stego(crate::domain::errors::StegoError::MalformedCoverData {
            reason: format!("write {}: {e}", path.display()),
        })
    })
}

fn fs_create_dir_all(path: &Path) -> Result<(), AppError> {
    std::fs::create_dir_all(path).map_err(|e| {
        AppError::Stego(crate::domain::errors::StegoError::MalformedCoverData {
            reason: format!("mkdir {}: {e}", path.display()),
        })
    })
}

fn map_media_error(error: crate::domain::errors::MediaError) -> AppError {
    match error {
        crate::domain::errors::MediaError::UnsupportedFormat { extension } => {
            AppError::Stego(crate::domain::errors::StegoError::UnsupportedCoverType {
                reason: format!("unsupported cover format: {extension}"),
            })
        }
        crate::domain::errors::MediaError::DecodeFailed { reason }
        | crate::domain::errors::MediaError::EncodeFailed { reason }
        | crate::domain::errors::MediaError::IoError { reason } => {
            AppError::Stego(crate::domain::errors::StegoError::MalformedCoverData { reason })
        }
    }
}

#[cfg(feature = "pdf")]
fn map_pdf_runner_error(error: crate::domain::errors::PdfError) -> AppError {
    match error {
        crate::domain::errors::PdfError::Encrypted => {
            AppError::Stego(crate::domain::errors::StegoError::UnsupportedCoverType {
                reason: "encrypted PDF documents are not supported".to_string(),
            })
        }
        crate::domain::errors::PdfError::ParseFailed { reason }
        | crate::domain::errors::PdfError::RenderFailed { reason, .. }
        | crate::domain::errors::PdfError::RebuildFailed { reason }
        | crate::domain::errors::PdfError::EmbedFailed { reason }
        | crate::domain::errors::PdfError::ExtractFailed { reason }
        | crate::domain::errors::PdfError::IoError { reason } => {
            AppError::Stego(crate::domain::errors::StegoError::MalformedCoverData { reason })
        }
        crate::domain::errors::PdfError::BindFailed { reason } => {
            AppError::Stego(crate::domain::errors::StegoError::UnsupportedCoverType {
                reason: format!("pdfium library is not available: {reason}"),
            })
        }
    }
}

fn load_cover_from_path(path: &Path, technique: StegoTechnique) -> Result<CoverMedia, AppError> {
    match technique {
        StegoTechnique::LsbAudio | StegoTechnique::PhaseEncoding | StegoTechnique::EchoHiding => {
            let loader = crate::adapters::media::AudioMediaLoader;
            loader.load(path).map_err(map_media_error)
        }
        StegoTechnique::PdfContentStream | StegoTechnique::PdfMetadata => load_pdf_cover(path),
        StegoTechnique::ZeroWidthText => {
            let data = fs_read(path)?;
            Ok(load_cover(technique, &data))
        }
        StegoTechnique::LsbImage
        | StegoTechnique::DctJpeg
        | StegoTechnique::Palette
        | StegoTechnique::CorpusSelection
        | StegoTechnique::DualPayload => {
            let loader = crate::adapters::media::ImageMediaLoader;
            loader.load(path).map_err(map_media_error)
        }
    }
}

#[cfg(feature = "pdf")]
fn load_pdf_cover(path: &Path) -> Result<CoverMedia, AppError> {
    use crate::domain::ports::PdfProcessor;

    let processor = crate::adapters::pdf::PdfProcessorImpl::default();
    processor.load_pdf(path).map_err(map_pdf_runner_error)
}

#[cfg(not(feature = "pdf"))]
fn load_pdf_cover(_path: &Path) -> Result<CoverMedia, AppError> {
    Err(AppError::Stego(
        crate::domain::errors::StegoError::UnsupportedCoverType {
            reason: "PDF support is not enabled in this build".to_string(),
        },
    ))
}

fn save_cover_to_path(media: &CoverMedia, path: &Path) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        fs_create_dir_all(parent)?;
    }

    match media.kind {
        CoverMediaKind::PngImage
        | CoverMediaKind::BmpImage
        | CoverMediaKind::JpegImage
        | CoverMediaKind::GifImage => {
            let loader = crate::adapters::media::ImageMediaLoader;
            loader.save(media, path).map_err(map_media_error)
        }
        CoverMediaKind::WavAudio => {
            let loader = crate::adapters::media::AudioMediaLoader;
            loader.save(media, path).map_err(map_media_error)
        }
        CoverMediaKind::PdfDocument => save_pdf_cover(media, path),
        CoverMediaKind::PlainText => fs_write(path, media.data.as_ref()),
    }
}

#[cfg(feature = "pdf")]
fn save_pdf_cover(media: &CoverMedia, path: &Path) -> Result<(), AppError> {
    use crate::domain::ports::PdfProcessor;

    let processor = crate::adapters::pdf::PdfProcessorImpl::default();
    processor
        .save_pdf(media, path)
        .map_err(map_pdf_runner_error)
}

#[cfg(not(feature = "pdf"))]
fn save_pdf_cover(_media: &CoverMedia, _path: &Path) -> Result<(), AppError> {
    Err(AppError::Stego(
        crate::domain::errors::StegoError::UnsupportedCoverType {
            reason: "PDF support is not enabled in this build".to_string(),
        },
    ))
}

fn serialise_cover_to_bytes(media: &CoverMedia) -> Result<Vec<u8>, AppError> {
    match media.kind {
        CoverMediaKind::PdfDocument | CoverMediaKind::PlainText => Ok(media.data.to_vec()),
        _ => {
            let temp_path = std::env::temp_dir().join(format!(
                "shadowforge-{}.{}",
                uuid::Uuid::new_v4(),
                cover_file_extension(media.kind)
            ));
            let result = (|| {
                save_cover_to_path(media, &temp_path)?;
                fs_read(&temp_path)
            })();
            let _ = std::fs::remove_file(&temp_path);
            result
        }
    }
}

fn load_cover_from_named_bytes(
    name: &str,
    technique: StegoTechnique,
    data: &[u8],
) -> Result<CoverMedia, AppError> {
    if technique == StegoTechnique::ZeroWidthText {
        return Ok(load_cover(technique, data));
    }

    let extension = Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_else(|| technique_file_extension(technique));
    let temp_path = std::env::temp_dir().join(format!(
        "shadowforge-{}.{}",
        uuid::Uuid::new_v4(),
        extension
    ));
    let result = (|| {
        fs_write(&temp_path, data)?;
        load_cover_from_path(&temp_path, technique)
    })();
    let _ = std::fs::remove_file(&temp_path);
    result
}

const fn cover_file_extension(kind: CoverMediaKind) -> &'static str {
    match kind {
        CoverMediaKind::PngImage => "png",
        CoverMediaKind::BmpImage => "bmp",
        CoverMediaKind::JpegImage => "jpg",
        CoverMediaKind::GifImage => "gif",
        CoverMediaKind::WavAudio => "wav",
        CoverMediaKind::PdfDocument => "pdf",
        CoverMediaKind::PlainText => "txt",
    }
}

const fn technique_file_extension(technique: StegoTechnique) -> &'static str {
    match technique {
        StegoTechnique::LsbAudio | StegoTechnique::PhaseEncoding | StegoTechnique::EchoHiding => {
            "wav"
        }
        StegoTechnique::PdfContentStream | StegoTechnique::PdfMetadata => "pdf",
        StegoTechnique::ZeroWidthText => "txt",
        StegoTechnique::DctJpeg => "jpg",
        StegoTechnique::LsbImage
        | StegoTechnique::Palette
        | StegoTechnique::CorpusSelection
        | StegoTechnique::DualPayload => "png",
    }
}

fn load_cover(technique: crate::domain::types::StegoTechnique, data: &[u8]) -> CoverMedia {
    let kind = match technique {
        crate::domain::types::StegoTechnique::LsbAudio
        | crate::domain::types::StegoTechnique::PhaseEncoding
        | crate::domain::types::StegoTechnique::EchoHiding => CoverMediaKind::WavAudio,
        crate::domain::types::StegoTechnique::ZeroWidthText => CoverMediaKind::PlainText,
        crate::domain::types::StegoTechnique::PdfContentStream
        | crate::domain::types::StegoTechnique::PdfMetadata => CoverMediaKind::PdfDocument,
        crate::domain::types::StegoTechnique::DctJpeg => CoverMediaKind::JpegImage,
        crate::domain::types::StegoTechnique::LsbImage
        | crate::domain::types::StegoTechnique::Palette
        | crate::domain::types::StegoTechnique::CorpusSelection
        | crate::domain::types::StegoTechnique::DualPayload => CoverMediaKind::PngImage,
    };
    CoverMedia {
        kind,
        data: bytes::Bytes::from(data.to_vec()),
        metadata: std::collections::HashMap::new(),
    }
}

/// Build an embedder for the given technique.
fn build_embedder(technique: crate::domain::types::StegoTechnique) -> Box<dyn EmbedTechnique> {
    use crate::domain::types::StegoTechnique;
    match technique {
        StegoTechnique::DctJpeg => Box::new(crate::adapters::stego::DctJpeg),
        StegoTechnique::Palette => Box::new(crate::adapters::stego::PaletteStego),
        StegoTechnique::LsbAudio => Box::new(crate::adapters::stego::LsbAudio),
        StegoTechnique::PhaseEncoding => Box::new(crate::adapters::stego::PhaseEncoding),
        StegoTechnique::EchoHiding => Box::new(crate::adapters::stego::EchoHiding),
        StegoTechnique::ZeroWidthText => Box::new(crate::adapters::stego::ZeroWidthText),
        StegoTechnique::PdfContentStream => build_pdf_content_stream_embedder(),
        StegoTechnique::PdfMetadata => build_pdf_metadata_embedder(),
        StegoTechnique::CorpusSelection => Box::new(UnsupportedTechnique::new(
            StegoTechnique::CorpusSelection,
            "corpus selection must use the corpus workflow, not generic embed",
        )),
        StegoTechnique::DualPayload => Box::new(UnsupportedTechnique::new(
            StegoTechnique::DualPayload,
            "dual-payload embedding must use the deniable embed workflow",
        )),
        StegoTechnique::LsbImage => Box::new(crate::adapters::stego::LsbImage::new()),
    }
}

/// Build an extractor for the given technique.
fn build_extractor(technique: crate::domain::types::StegoTechnique) -> Box<dyn ExtractTechnique> {
    use crate::domain::types::StegoTechnique;
    match technique {
        StegoTechnique::DctJpeg => Box::new(crate::adapters::stego::DctJpeg),
        StegoTechnique::Palette => Box::new(crate::adapters::stego::PaletteStego),
        StegoTechnique::LsbAudio => Box::new(crate::adapters::stego::LsbAudio),
        StegoTechnique::PhaseEncoding => Box::new(crate::adapters::stego::PhaseEncoding),
        StegoTechnique::EchoHiding => Box::new(crate::adapters::stego::EchoHiding),
        StegoTechnique::ZeroWidthText => Box::new(crate::adapters::stego::ZeroWidthText),
        StegoTechnique::PdfContentStream => build_pdf_content_stream_extractor(),
        StegoTechnique::PdfMetadata => build_pdf_metadata_extractor(),
        StegoTechnique::CorpusSelection => Box::new(UnsupportedTechnique::new(
            StegoTechnique::CorpusSelection,
            "corpus selection must use the corpus workflow, not generic extract",
        )),
        StegoTechnique::DualPayload => Box::new(UnsupportedTechnique::new(
            StegoTechnique::DualPayload,
            "dual-payload extraction must use the deniable extraction workflow",
        )),
        StegoTechnique::LsbImage => Box::new(crate::adapters::stego::LsbImage::new()),
    }
}

#[cfg(feature = "pdf")]
fn build_pdf_content_stream_embedder() -> Box<dyn EmbedTechnique> {
    Box::new(crate::adapters::pdf::PdfContentStreamStego::new())
}

#[cfg(not(feature = "pdf"))]
fn build_pdf_content_stream_embedder() -> Box<dyn EmbedTechnique> {
    Box::new(UnsupportedTechnique::new(
        crate::domain::types::StegoTechnique::PdfContentStream,
        "PDF support is not enabled in this build",
    ))
}

#[cfg(feature = "pdf")]
fn build_pdf_metadata_embedder() -> Box<dyn EmbedTechnique> {
    Box::new(crate::adapters::pdf::PdfMetadataStego::new())
}

#[cfg(not(feature = "pdf"))]
fn build_pdf_metadata_embedder() -> Box<dyn EmbedTechnique> {
    Box::new(UnsupportedTechnique::new(
        crate::domain::types::StegoTechnique::PdfMetadata,
        "PDF support is not enabled in this build",
    ))
}

#[cfg(feature = "pdf")]
fn build_pdf_content_stream_extractor() -> Box<dyn ExtractTechnique> {
    Box::new(crate::adapters::pdf::PdfContentStreamStego::new())
}

#[cfg(not(feature = "pdf"))]
fn build_pdf_content_stream_extractor() -> Box<dyn ExtractTechnique> {
    Box::new(UnsupportedTechnique::new(
        crate::domain::types::StegoTechnique::PdfContentStream,
        "PDF support is not enabled in this build",
    ))
}

#[cfg(feature = "pdf")]
fn build_pdf_metadata_extractor() -> Box<dyn ExtractTechnique> {
    Box::new(crate::adapters::pdf::PdfMetadataStego::new())
}

#[cfg(not(feature = "pdf"))]
fn build_pdf_metadata_extractor() -> Box<dyn ExtractTechnique> {
    Box::new(UnsupportedTechnique::new(
        crate::domain::types::StegoTechnique::PdfMetadata,
        "PDF support is not enabled in this build",
    ))
}

#[derive(Debug)]
struct UnsupportedTechnique {
    technique: crate::domain::types::StegoTechnique,
    reason: &'static str,
}

impl UnsupportedTechnique {
    const fn new(technique: crate::domain::types::StegoTechnique, reason: &'static str) -> Self {
        Self { technique, reason }
    }
}

impl EmbedTechnique for UnsupportedTechnique {
    fn technique(&self) -> crate::domain::types::StegoTechnique {
        self.technique
    }

    fn capacity(&self, _cover: &CoverMedia) -> Result<crate::domain::types::Capacity, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: self.reason.to_string(),
        })
    }

    fn embed(&self, _cover: CoverMedia, _payload: &Payload) -> Result<CoverMedia, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: self.reason.to_string(),
        })
    }
}

impl ExtractTechnique for UnsupportedTechnique {
    fn technique(&self) -> crate::domain::types::StegoTechnique {
        self.technique
    }

    fn extract(&self, _stego: &CoverMedia) -> Result<Payload, StegoError> {
        Err(StegoError::UnsupportedCoverType {
            reason: self.reason.to_string(),
        })
    }
}

const fn resolve_technique(t: cli::Technique) -> crate::domain::types::StegoTechnique {
    match t {
        cli::Technique::Lsb => crate::domain::types::StegoTechnique::LsbImage,
        cli::Technique::Dct => crate::domain::types::StegoTechnique::DctJpeg,
        cli::Technique::Palette => crate::domain::types::StegoTechnique::Palette,
        cli::Technique::LsbAudio => crate::domain::types::StegoTechnique::LsbAudio,
        cli::Technique::Phase => crate::domain::types::StegoTechnique::PhaseEncoding,
        cli::Technique::Echo => crate::domain::types::StegoTechnique::EchoHiding,
        cli::Technique::ZeroWidth => crate::domain::types::StegoTechnique::ZeroWidthText,
        cli::Technique::PdfStream => crate::domain::types::StegoTechnique::PdfContentStream,
        cli::Technique::PdfMeta => crate::domain::types::StegoTechnique::PdfMetadata,
        cli::Technique::Corpus => crate::domain::types::StegoTechnique::CorpusSelection,
    }
}

fn resolve_profile(
    profile: cli::Profile,
    platform: Option<cli::Platform>,
) -> crate::domain::types::EmbeddingProfile {
    match profile {
        cli::Profile::Standard => crate::domain::types::EmbeddingProfile::Standard,
        cli::Profile::Adaptive => crate::domain::types::EmbeddingProfile::default_adaptive(),
        cli::Profile::Survivable => {
            let p = platform.map_or(crate::domain::types::PlatformProfile::Instagram, |pl| {
                resolve_platform(pl)
            });
            crate::domain::types::EmbeddingProfile::CompressionSurvivable { platform: p }
        }
    }
}

const fn resolve_platform(p: cli::Platform) -> crate::domain::types::PlatformProfile {
    match p {
        cli::Platform::Instagram => crate::domain::types::PlatformProfile::Instagram,
        cli::Platform::Twitter => crate::domain::types::PlatformProfile::Twitter,
        cli::Platform::Whatsapp => crate::domain::types::PlatformProfile::WhatsApp,
        cli::Platform::Telegram => crate::domain::types::PlatformProfile::Telegram,
        cli::Platform::Imgur => crate::domain::types::PlatformProfile::Imgur,
    }
}

const fn resolve_archive_format(f: cli::ArchiveFormat) -> crate::domain::types::ArchiveFormat {
    match f {
        cli::ArchiveFormat::Zip => crate::domain::types::ArchiveFormat::Zip,
        cli::ArchiveFormat::Tar => crate::domain::types::ArchiveFormat::Tar,
        cli::ArchiveFormat::TarGz => crate::domain::types::ArchiveFormat::TarGz,
    }
}

/// Collect cover file paths — if the argument is a glob pattern expand it,
/// otherwise treat it as a directory and list its files.
fn collect_cover_paths(pattern: &str) -> Result<Vec<PathBuf>, AppError> {
    let path = PathBuf::from(pattern);
    let paths: Vec<PathBuf> = if path.is_dir() {
        std::fs::read_dir(&path)
            .map_err(
                |_| crate::domain::errors::DistributionError::InsufficientCovers {
                    needed: 1,
                    got: 0,
                },
            )?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect()
    } else if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
        glob::glob(pattern)
            .map_err(
                |_| crate::domain::errors::DistributionError::InsufficientCovers {
                    needed: 1,
                    got: 0,
                },
            )?
            .filter_map(Result::ok)
            .filter(|p| p.is_file())
            .collect()
    } else {
        // Treat as a literal file list (single file)
        vec![path]
    };

    if paths.is_empty() {
        return Err(
            crate::domain::errors::DistributionError::InsufficientCovers { needed: 1, got: 0 }
                .into(),
        );
    }
    Ok(paths)
}

fn load_watermark_tags(
    dir: &Path,
) -> Result<Vec<crate::domain::types::WatermarkTripwireTag>, AppError> {
    let mut tags = Vec::new();
    if dir.is_dir() {
        let entries = std::fs::read_dir(dir).map_err(|e| {
            crate::domain::errors::OpsecError::WatermarkError {
                reason: format!("read dir: {e}"),
            }
        })?;
        for entry in entries {
            let entry = entry.map_err(|e: std::io::Error| {
                crate::domain::errors::OpsecError::WatermarkError {
                    reason: format!("dir entry: {e}"),
                }
            })?;
            let path = entry.path();
            if path.is_file() {
                // Parse tag from file: content is a recipient UUID string, used as seed too
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let id_str = content.trim();
                    let rid = uuid::Uuid::parse_str(id_str).map_err(|e| {
                        crate::domain::errors::OpsecError::WatermarkError {
                            reason: format!("invalid UUID in {}: {e}", path.display()),
                        }
                    })?;
                    tags.push(crate::domain::types::WatermarkTripwireTag {
                        recipient_id: rid,
                        embedding_seed: id_str.as_bytes().to_vec(),
                    });
                }
            }
        }
    }
    Ok(tags)
}

#[cfg(test)]
mod tests {
    use super::{
        build_embedder, build_extractor, cmd_extract, cmd_keygen, load_cover, load_cover_from_path,
        save_cover_to_path,
    };
    use crate::application::services::{AppError, DeniableEmbedService};
    use crate::domain::errors::CryptoError;
    use crate::domain::types::{CoverMediaKind, StegoTechnique};
    use crate::interface::cli;
    use clap::Parser as _;
    use image::{DynamicImage, Rgba, RgbaImage};
    use std::fs;
    use tempfile::tempdir;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn dct_cover_is_classified_as_jpeg() {
        let cover = load_cover(StegoTechnique::DctJpeg, b"jpeg");
        assert_eq!(cover.kind, CoverMediaKind::JpegImage);
    }

    #[test]
    fn pdf_cover_is_classified_as_pdf() {
        let cover = load_cover(StegoTechnique::PdfContentStream, b"%PDF-1.7");
        assert_eq!(cover.kind, CoverMediaKind::PdfDocument);
    }

    #[test]
    fn pdf_content_stream_embedder_uses_pdf_technique() {
        let embedder = build_embedder(StegoTechnique::PdfContentStream);
        assert_eq!(embedder.technique(), StegoTechnique::PdfContentStream);
    }

    #[test]
    fn pdf_metadata_extractor_uses_pdf_technique() {
        let extractor = build_extractor(StegoTechnique::PdfMetadata);
        assert_eq!(extractor.technique(), StegoTechnique::PdfMetadata);
    }

    #[test]
    fn corpus_embedder_is_not_rewritten_as_lsb_image() {
        let embedder = build_embedder(StegoTechnique::CorpusSelection);
        assert_eq!(embedder.technique(), StegoTechnique::CorpusSelection);
    }

    #[test]
    fn file_backed_image_covers_use_media_loader() -> TestResult {
        let dir = tempdir()?;
        let input_path = dir.path().join("cover.png");
        let output_path = dir.path().join("roundtrip.png");

        let image = DynamicImage::ImageRgba8(RgbaImage::from_pixel(3, 2, Rgba([1, 2, 3, 255])));
        image.save(&input_path)?;

        let cover = load_cover_from_path(&input_path, StegoTechnique::LsbImage)?;
        assert_eq!(cover.kind, CoverMediaKind::PngImage);
        assert_eq!(cover.metadata.get("width"), Some(&"3".to_string()));
        assert_eq!(cover.metadata.get("height"), Some(&"2".to_string()));

        save_cover_to_path(&cover, &output_path)?;
        let written = fs::read(output_path)?;
        assert!(!written.is_empty());
        Ok(())
    }

    #[test]
    fn extract_uses_deniable_key_path_when_provided() -> TestResult {
        let dir = tempdir()?;
        let cover_path = dir.path().join("cover.png");
        let input_path = dir.path().join("input.png");
        let output_path = dir.path().join("output.bin");
        let key_path = dir.path().join("primary.key");

        let image = DynamicImage::ImageRgba8(RgbaImage::from_pixel(40, 40, Rgba([0, 0, 0, 255])));
        image.save(&cover_path)?;

        let primary_key = vec![7u8; 32];
        let decoy_key = vec![9u8; 32];
        let pair = crate::domain::types::DeniablePayloadPair {
            real_payload: b"real secret".to_vec(),
            decoy_payload: b"decoy".to_vec(),
        };
        let keys = crate::domain::types::DeniableKeySet {
            primary_key: primary_key.clone(),
            decoy_key,
        };
        let cover = load_cover_from_path(&cover_path, StegoTechnique::LsbImage)?;
        let deniable = crate::adapters::stego::DualPayloadEmbedder;
        let embedder = build_embedder(StegoTechnique::LsbImage);
        let stego =
            DeniableEmbedService::embed_dual(cover, &pair, &keys, embedder.as_ref(), &deniable)?;

        save_cover_to_path(&stego, &input_path)?;
        fs::write(&key_path, &primary_key)?;

        let args = cli::ExtractArgs {
            input: input_path,
            output: output_path.clone(),
            technique: cli::Technique::Lsb,
            key: Some(key_path),
            amnesia: false,
        };

        cmd_extract(&args)?;

        let extracted = fs::read(output_path)?;
        assert_eq!(extracted, b"real secret");
        Ok(())
    }

    #[test]
    fn keygen_sign_produces_signature_artifact() -> TestResult {
        let dir = tempdir()?;
        let keys_dir = dir.path().join("keys");
        let msg_path = dir.path().join("message.bin");
        let sig_path = dir.path().join("message.sig");

        let generate = cli::KeygenArgs {
            subcmd: None,
            algorithm: Some(cli::Algorithm::Dilithium3),
            output: Some(keys_dir.clone()),
        };
        cmd_keygen(&generate)?;

        fs::write(&msg_path, b"hello signer")?;
        let sign = cli::KeygenArgs {
            subcmd: Some(cli::KeygenSubcommand::Sign {
                input: msg_path,
                secret_key: keys_dir.join("secret.key"),
                output: sig_path.clone(),
            }),
            algorithm: None,
            output: None,
        };
        cmd_keygen(&sign)?;

        let sig = fs::read(sig_path)?;
        assert!(!sig.is_empty());
        Ok(())
    }

    #[test]
    fn keygen_verify_reports_success_and_failure_status() -> TestResult {
        let dir = tempdir()?;
        let keys_dir = dir.path().join("keys");
        let msg_path = dir.path().join("message.bin");
        let tampered_path = dir.path().join("message_tampered.bin");
        let sig_path = dir.path().join("message.sig");

        let generate = cli::KeygenArgs {
            subcmd: None,
            algorithm: Some(cli::Algorithm::Dilithium3),
            output: Some(keys_dir.clone()),
        };
        cmd_keygen(&generate)?;

        fs::write(&msg_path, b"signed message")?;
        fs::write(&tampered_path, b"signed message with tamper")?;

        let sign = cli::KeygenArgs {
            subcmd: Some(cli::KeygenSubcommand::Sign {
                input: msg_path.clone(),
                secret_key: keys_dir.join("secret.key"),
                output: sig_path.clone(),
            }),
            algorithm: None,
            output: None,
        };
        cmd_keygen(&sign)?;

        let verify_ok = cli::KeygenArgs {
            subcmd: Some(cli::KeygenSubcommand::Verify {
                input: msg_path,
                public_key: keys_dir.join("public.key"),
                signature: sig_path.clone(),
            }),
            algorithm: None,
            output: None,
        };
        assert!(cmd_keygen(&verify_ok).is_ok());

        let verify_fail = cli::KeygenArgs {
            subcmd: Some(cli::KeygenSubcommand::Verify {
                input: tampered_path,
                public_key: keys_dir.join("public.key"),
                signature: sig_path,
            }),
            algorithm: None,
            output: None,
        };
        let err = cmd_keygen(&verify_fail).err();
        assert!(matches!(
            err,
            Some(AppError::Crypto(CryptoError::VerificationFailed { .. }))
        ));
        Ok(())
    }

    // ─── format_analysis_report ───────────────────────────────────────────

    use super::format_analysis_report;
    use crate::domain::types::{
        AiWatermarkAssessment, AnalysisReport, Capacity, DetectabilityRisk, SpectralScore,
        StegoTechnique as ST,
    };

    fn base_report() -> AnalysisReport {
        AnalysisReport {
            technique: ST::LsbImage,
            cover_capacity: Capacity {
                bytes: 1024,
                technique: ST::LsbImage,
            },
            chi_square_score: std::f64::consts::PI,
            detectability_risk: DetectabilityRisk::Low,
            recommended_max_payload_bytes: 512,
            ai_watermark: None,
            spectral_score: None,
        }
    }

    #[test]
    fn format_report_contains_core_fields() {
        let report = base_report();
        let out = format_analysis_report(&report);
        assert!(out.contains("LsbImage"), "technique should appear");
        assert!(out.contains("1024 bytes"), "capacity should appear");
        assert!(out.contains("3.14 dB"), "chi-square should appear");
        assert!(out.contains("Low"), "risk should appear");
        assert!(out.contains("512 bytes"), "recommended max should appear");
    }

    #[test]
    fn format_report_omits_spectral_section_when_none() {
        let report = base_report();
        let out = format_analysis_report(&report);
        assert!(
            !out.contains("Spectral Detectability"),
            "spectral section must be absent when score is None"
        );
    }

    #[test]
    fn format_report_includes_spectral_section_when_present() {
        let mut report = base_report();
        report.spectral_score = Some(SpectralScore {
            phase_coherence_drop: 0.1234,
            carrier_snr_drop_db: -2.5,
            sample_pair_asymmetry: 0.0081,
            combined_risk: DetectabilityRisk::Medium,
        });
        let out = format_analysis_report(&report);
        assert!(
            out.contains("Spectral Detectability"),
            "section header must appear"
        );
        assert!(out.contains("0.1234"), "phase coherence drop should appear");
        assert!(out.contains("-2.50 dB"), "SNR drop should appear");
        assert!(
            out.contains("0.0081"),
            "sample-pair asymmetry should appear"
        );
        assert!(out.contains("Medium"), "spectral risk should appear");
    }

    #[test]
    fn format_report_spectral_does_not_bleed_into_core_output() {
        let report = base_report();
        let out = format_analysis_report(&report);
        // Core fields still present even without spectral score
        assert!(out.contains("Technique"));
        assert!(out.contains("Chi-square"));
        assert!(out.contains("Recommended"));
    }

    // ─── CLI subcommand safety ─────────────────────────────────────────────

    /// Verify that clap rejects an unrecognised top-level subcommand without
    /// panicking.  This documents the contract: unknown input → `Err`, not a
    /// panic or a silent `Ok`.
    #[test]
    fn unknown_top_level_subcommand_is_rejected() {
        let result = cli::Cli::try_parse_from(["shadowforge", "not-a-real-command"]);
        assert!(
            result.is_err(),
            "clap must reject unknown top-level subcommands with Err"
        );
    }

    /// Verify that clap rejects an unrecognised sub-subcommand under a known
    /// command without panicking.
    #[test]
    fn unknown_sub_subcommand_is_rejected() {
        let result = cli::Cli::try_parse_from(["shadowforge", "keygen", "not-a-real-subcmd"]);
        assert!(
            result.is_err(),
            "clap must reject unknown sub-subcommands with Err"
        );
    }

    #[test]
    fn version_subcommand_is_accepted() {
        let result = cli::Cli::try_parse_from(["shadowforge", "version"]);
        assert!(
            result.is_ok(),
            "version subcommand must parse without error"
        );
    }

    #[test]
    fn format_report_includes_ai_watermark_section_when_present() {
        let mut report = base_report();
        report.ai_watermark = Some(AiWatermarkAssessment {
            detected: true,
            model_id: Some("gemini".to_string()),
            confidence: 0.875,
            matched_strong_bins: 7,
            total_strong_bins: 8,
        });

        let out = format_analysis_report(&report);
        assert!(out.contains("AI Watermark Detection"));
        assert!(out.contains("yes"));
        assert!(out.contains("gemini"));
        assert!(out.contains("0.8750"));
        assert!(out.contains("7/8"));
    }
}

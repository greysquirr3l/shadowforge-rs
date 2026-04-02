//! CLI runner — dispatches parsed commands to application services.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use clap::Parser;

use crate::application::services::{
    AnalyseService, AppError, ArchiveService, EmbedService, ExtractService, KeyGenService,
    ScrubService,
};
use crate::domain::types::{CoverMedia, CoverMediaKind, Payload};

use super::cli::{self, Cli, Commands};

/// Run the CLI. Returns `Ok(())` on success.
///
/// # Errors
/// Returns [`AppError`] on any service failure.
pub fn run() -> Result<(), AppError> {
    let cli = Cli::parse();
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
        Commands::Completions(args) => {
            cmd_completions(&args);
            Ok(())
        }
    }
}

fn print_version() {
    let version = env!("CARGO_PKG_VERSION");
    let sha = option_env!("VERGEN_GIT_SHA").unwrap_or("unknown");
    println!("shadowforge {version} ({sha})");
}

// ─── Keygen ───────────────────────────────────────────────────────────────────

fn cmd_keygen(args: &cli::KeygenArgs) -> Result<(), AppError> {
    let dir = &args.output;
    fs_create_dir_all(dir)?;

    match args.algorithm {
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
        let cover_bytes = fs_read(cover_path)?;
        let cover = load_cover(technique, &cover_bytes);

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
        fs_write(&args.output, stego.data.as_ref())?;
        eprintln!("Deniable embedding complete");
    } else {
        let cover_path = args.cover.as_ref().ok_or_else(|| {
            crate::domain::errors::StegoError::MalformedCoverData {
                reason: "--cover is required when not using --amnesia".into(),
            }
        })?;
        let cover_bytes = fs_read(cover_path)?;
        let cover = load_cover(technique, &cover_bytes);
        let stego = EmbedService::embed(cover, &payload, embedder.as_ref())?;
        fs_write(&args.output, stego.data.as_ref())?;
        eprintln!("Embedded {} bytes", payload.len());
    }
    Ok(())
}

// ─── Extract ──────────────────────────────────────────────────────────────────

fn cmd_extract(args: &cli::ExtractArgs) -> Result<(), AppError> {
    let technique = resolve_technique(args.technique);
    let extractor = build_extractor(technique);

    if args.amnesia {
        let mut buf = Vec::new();
        io::stdin().lock().read_to_end(&mut buf).map_err(|e| {
            crate::domain::errors::StegoError::MalformedCoverData {
                reason: format!("stdin read: {e}"),
            }
        })?;
        let cover = load_cover(technique, &buf);
        let payload = ExtractService::extract(&cover, extractor.as_ref())?;
        io::stdout().write_all(payload.as_bytes()).map_err(|e| {
            crate::domain::errors::StegoError::MalformedCoverData {
                reason: format!("stdout write: {e}"),
            }
        })?;
    } else {
        let stego_bytes = fs_read(&args.input)?;
        let stego = load_cover(technique, &stego_bytes);
        let payload = ExtractService::extract(&stego, extractor.as_ref())?;
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
        .map(|p| {
            let data = fs_read(p)?;
            Ok(load_cover(technique, &data))
        })
        .collect();
    let covers = covers?;

    let profile = resolve_profile(args.profile, args.platform);
    let distributor = crate::adapters::distribution::DistributorImpl;

    let stego_covers = crate::application::services::DistributeService::distribute(
        &payload,
        covers,
        &profile,
        &distributor,
        embedder.as_ref(),
    )?;

    let files: Vec<(String, Vec<u8>)> = stego_covers
        .iter()
        .enumerate()
        .map(|(i, c)| (format!("shard_{i:04}.png"), c.data.to_vec()))
        .collect();
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
    eprintln!(
        "Distributed into {} shards → {}",
        stego_covers.len(),
        args.output_archive.display()
    );
    Ok(())
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
        .map(|(_, data)| load_cover(technique, data))
        .collect();

    let reconstructor = crate::adapters::reconstruction::ReconstructorImpl::new(
        args.data_shards,
        args.parity_shards,
        Vec::new(),
        0,
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

fn cmd_analyse(args: &cli::AnalyseArgs) -> Result<(), AppError> {
    let technique = resolve_technique(args.technique);
    let cover_bytes = fs_read(&args.cover)?;
    let cover = load_cover(technique, &cover_bytes);
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
        println!("Technique:     {:?}", report.technique);
        println!("Capacity:      {} bytes", report.cover_capacity.bytes);
        println!("Chi-square:    {:.2} dB", report.chi_square_score);
        println!("Risk:          {:?}", report.detectability_risk);
        println!(
            "Recommended:   {} bytes",
            report.recommended_max_payload_bytes
        );
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
    let cover_bytes = fs_read(&args.cover)?;
    let cover = load_cover(technique, &cover_bytes);
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
    fs_write(&args.output, stego.data.as_ref())?;
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
            let cover_bytes = fs_read(cover)?;
            let cover_media =
                load_cover(crate::domain::types::StegoTechnique::LsbImage, &cover_bytes);
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
            fs_write(output, stego.data.as_ref())?;
            eprintln!("Tripwire embedded for {recipient_id}");
        }
        cli::WatermarkSubcommand::Identify { cover, tags } => {
            let cover_bytes = fs_read(cover)?;
            let cover_media =
                load_cover(crate::domain::types::StegoTechnique::LsbImage, &cover_bytes);
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
    use crate::domain::ports::CorpusIndex;

    let index = crate::adapters::corpus::CorpusIndexImpl::new();
    match &args.subcmd {
        cli::CorpusSubcommand::Build { dir } => {
            let count = index.build_index(dir)?;
            eprintln!("Indexed {count} images from {}", dir.display());
        }
        cli::CorpusSubcommand::Search {
            input,
            technique,
            top,
        } => {
            let data = fs_read(input)?;
            let payload = Payload::from_bytes(data);
            let tech = resolve_technique(*technique);
            let results = index.search(&payload, tech, *top)?;
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

fn cmd_completions(args: &cli::CompletionsArgs) {
    use clap::CommandFactory;
    use clap_complete::generate;

    let mut cmd = Cli::command();
    generate(args.shell, &mut cmd, "shadowforge", &mut io::stdout());
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

fn load_cover(technique: crate::domain::types::StegoTechnique, data: &[u8]) -> CoverMedia {
    let kind = match technique {
        crate::domain::types::StegoTechnique::LsbAudio
        | crate::domain::types::StegoTechnique::PhaseEncoding
        | crate::domain::types::StegoTechnique::EchoHiding => CoverMediaKind::WavAudio,
        crate::domain::types::StegoTechnique::ZeroWidthText => CoverMediaKind::PlainText,
        crate::domain::types::StegoTechnique::PdfContentStream
        | crate::domain::types::StegoTechnique::PdfMetadata => CoverMediaKind::PdfDocument,
        crate::domain::types::StegoTechnique::LsbImage
        | crate::domain::types::StegoTechnique::DctJpeg
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
fn build_embedder(
    technique: crate::domain::types::StegoTechnique,
) -> Box<dyn crate::domain::ports::EmbedTechnique> {
    use crate::domain::types::StegoTechnique;
    match technique {
        StegoTechnique::DctJpeg => Box::new(crate::adapters::stego::DctJpeg),
        StegoTechnique::Palette => Box::new(crate::adapters::stego::PaletteStego),
        StegoTechnique::LsbAudio => Box::new(crate::adapters::stego::LsbAudio),
        StegoTechnique::PhaseEncoding => Box::new(crate::adapters::stego::PhaseEncoding),
        StegoTechnique::EchoHiding => Box::new(crate::adapters::stego::EchoHiding),
        StegoTechnique::ZeroWidthText => Box::new(crate::adapters::stego::ZeroWidthText),
        // PDF/Corpus/Dual fall back to LSB — PDF needs PdfProcessor not available here
        StegoTechnique::LsbImage
        | StegoTechnique::PdfContentStream
        | StegoTechnique::PdfMetadata
        | StegoTechnique::CorpusSelection
        | StegoTechnique::DualPayload => Box::new(crate::adapters::stego::LsbImage::new()),
    }
}

/// Build an extractor for the given technique.
fn build_extractor(
    technique: crate::domain::types::StegoTechnique,
) -> Box<dyn crate::domain::ports::ExtractTechnique> {
    use crate::domain::types::StegoTechnique;
    match technique {
        StegoTechnique::DctJpeg => Box::new(crate::adapters::stego::DctJpeg),
        StegoTechnique::Palette => Box::new(crate::adapters::stego::PaletteStego),
        StegoTechnique::LsbAudio => Box::new(crate::adapters::stego::LsbAudio),
        StegoTechnique::PhaseEncoding => Box::new(crate::adapters::stego::PhaseEncoding),
        StegoTechnique::EchoHiding => Box::new(crate::adapters::stego::EchoHiding),
        StegoTechnique::ZeroWidthText => Box::new(crate::adapters::stego::ZeroWidthText),
        StegoTechnique::LsbImage
        | StegoTechnique::PdfContentStream
        | StegoTechnique::PdfMetadata
        | StegoTechnique::CorpusSelection
        | StegoTechnique::DualPayload => Box::new(crate::adapters::stego::LsbImage::new()),
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
        cli::Profile::Adaptive => crate::domain::types::EmbeddingProfile::Adaptive {
            max_detectability_db: -12.0,
        },
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

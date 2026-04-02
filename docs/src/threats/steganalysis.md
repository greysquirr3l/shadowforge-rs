# Automated Steganalysis

## Threat

Nation-state adversaries deploy automated steganalysis tools (Aletheia, StegExpose, ensemble classifiers) at infrastructure scale to detect steganographic modifications in images transiting networks and platforms.

## Countermeasures

### Adaptive Embedding

The `AdaptiveEmbedder` uses STC-inspired permutation optimisation to minimise the statistical footprint of embedding. It bounds a detectability budget, choosing which cover bits to modify to minimise distortion.

```bash
shadowforge embed --input secret.txt --cover photo.png --output stego.png \
  --technique lsb --profile adaptive
```

### Cover Profile Matching

The `CoverProfileMatcher` analyses camera model fingerprints and noise patterns in the cover image. Embedding parameters are adjusted to preserve these natural statistical signatures.

### Compression-Survivable Embedding

Social media platforms aggressively recompress uploaded images. The `CompressionSurvivableEmbedder` ensures payloads survive this recompression for specific target platforms.

```bash
shadowforge embed --input secret.txt --cover photo.jpg --output stego.jpg \
  --technique dct --profile survivable --platform twitter
```

### Corpus Steganography

The most powerful countermeasure: instead of modifying a cover at all, find one whose existing bit patterns naturally encode the payload. Zero modifications means zero statistical evidence.

```bash
shadowforge corpus select --index corpus.idx --payload secret.txt --output cover.png
```

## Residual Risk

Targeted, manual analysis by a skilled steganalyst examining a specific file remains difficult to completely defeat. Adaptive embedding raises the bar significantly but does not guarantee undetectability against all possible classifiers.

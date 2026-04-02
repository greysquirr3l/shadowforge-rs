# Residual Risks

No tool provides absolute security. shadowforge raises the cost and complexity of adversary actions but has known limitations:

## Pre-Audit Status

shadowforge-rs has not undergone a formal security audit. Undiscovered vulnerabilities may exist in the cryptographic implementation, steganographic algorithms, or memory handling.

## Specific Limitations

1. **Time-lock puzzles** provide practical delay, not cryptographic guarantees. Hardware advances (especially ASICs) could reduce effective delay times.

2. **Deniable steganography** is defeated if the adversary obtains both the primary and decoy keys. Key management discipline is essential.

3. **Stylometric scrubbing** is statistical and partial. Authors with highly distinctive styles may retain identifiable residual patterns.

4. **Corpus steganography** effectiveness scales with corpus size. A small corpus may not contain a sufficiently close match.

5. **Amnesiac mode** protects against disk forensics but not against cold-boot attacks or hardware memory forensics.

6. **Compression-survivable embedding** is calibrated to current platform recompression settings. Platform changes may break payload recovery.

7. **Side channels** beyond software scope (power analysis, electromagnetic emanation, acoustic cryptanalysis) are not addressed.

## Complementary Tools

shadowforge should be used alongside, not instead of:

- **Signal** — end-to-end encrypted messaging
- **Tor / Tails** — network anonymity
- **VeraCrypt** — full-disk/volume encryption
- **Qubes OS** — compartmentalised computing

## Responsible Disclosure

If you discover a vulnerability, see the [Security Policy](../architecture/security-policy.md) for reporting instructions.

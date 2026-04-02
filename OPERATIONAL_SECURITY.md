`# Operational Security Guide

**For journalists, whistleblowers, and their editors.**

This guide translates shadowforge-rs features into concrete operational
procedures for common threat scenarios. Read `THREAT_MODEL.md` first to
understand the adversary model.

> ⚠️ shadowforge-rs is pre-audit software. Use it as a supplementary layer
> alongside established tools (Signal, Tor, SecureDrop), not as a replacement.

---

## Scenario 1: Crossing a Border with Sensitive Material

**Goal**: Carry sensitive material across a border checkpoint without it
being readable even if your device is seized and you are compelled to hand
over keys.

### Preparation (before travel)

1. **Generate a key pair for deniable embedding:**

   ```bash
   shadowforge keygen --algorithm kyber1024 --output ~/keys/real/
   shadowforge keygen --algorithm kyber1024 --output ~/keys/decoy/
   ```

2. **Prepare your decoy payload** — something plausible and innocent:
   a press release, a draft article, a public document. This is what you
   hand over under duress.

3. **Scrub the real payload's style** to destroy stylometric fingerprints:

   ```bash
   shadowforge scrub --input real_document.txt --output real_scrubbed.txt \
       --avg-sentence-len 18 --vocab-size 10000
   ```

4. **Embed both payloads deniably:**

   ```bash
   shadowforge embed \
       --input real_scrubbed.txt \
       --cover photo.jpg \
       --output travel_photo.jpg \
       --key ~/keys/real/public.key \
       --technique lsb \
       --deniable \
       --decoy-payload decoy_document.txt \
       --decoy-key ~/keys/decoy/public.key
   ```

5. **Delete the real key from your device.** Leave only the decoy key.
   Send the real key to a trusted contact in another jurisdiction via a
   secure channel. You now cannot decrypt the real payload yourself — which
   is the point.

### At the border

- If compelled to demonstrate: run `shadowforge extract` with the decoy key.
  The output is the innocent decoy document. There is no cryptographic way
  for an adversary to prove a second payload exists without your real key.
- The cover image is identical regardless of which key you use.

### After arrival

- Retrieve the real key from your trusted contact.
- Extract the real payload on a clean device.

### Configure panic wipe (optional but recommended)

Create `~/.shadowforge-panic.toml`:

```toml
key_paths  = ["/home/user/keys/real/secret.key", "/home/user/keys/decoy/secret.key"]
config_paths = ["/home/user/.shadowforge-panic.toml"]
temp_dirs  = ["/tmp/shadowforge"]
```

If seizure is imminent, run (looks like a failed extraction attempt):

```bash
shadowforge panic --key ~/keys/real/secret.key
```

Process exits `0` with no output. All keys are overwritten 3 times and deleted.

---

## Scenario 2: Getting a Document Out via a Dead Drop

**Goal**: Transfer a document to a journalist without any direct communication
between source and journalist — no email, no file transfer, no messaging.

### Source side

1. **Generate keys** (one-time, keep secret key secure):

   ```bash
   shadowforge keygen --algorithm kyber1024 --output ~/keys/
   ```

2. **Share the public key** with the journalist via an out-of-band channel
   (printed QR code, in-person exchange, SecureDrop).

3. **Scrub the document:**

   ```bash
   shadowforge scrub --input leaked_document.txt --output scrubbed.txt
   ```

4. **Encode for the target platform:**

   ```bash
   shadowforge dead-drop encode \
       --cover stock_photo.jpg \
       --input scrubbed.txt \
       --platform instagram \
       --key ~/keys/public.key \
       --output upload_photo.jpg \
       --manifest-output retrieval.json
   ```

5. **Post `upload_photo.jpg` to the agreed public account.**
   Share `retrieval.json` (contains only: platform, URL pattern, technique —
   not the key or payload) with the journalist via a separate channel.

### Journalist side

1. Download the image from the public URL.
2. Extract using the agreed technique and their copy of the public key
   (used for verification — the real decryption uses the shared secret
   established via KEM at embed time):

   ```bash
   shadowforge extract \
       --input downloaded_photo.jpg \
       --key ~/keys/secret.key \
       --output recovered_document.txt \
       --technique lsb
   ```

**Why this works**: No direct communication between source and journalist
ever occurs. The cover image passes through the public platform's
infrastructure. Traffic analysis shows only: an anonymous account posted
a photo. The journalist retrieved a public photo. No connection.

---

## Scenario 3: Distributing a Document Across Multiple Trusted Contacts

**Goal**: Ensure a document survives even if some trusted contacts are
compromised, arrested, or lose access — while requiring cooperation across
multiple jurisdictions to reconstruct.

1. **Prepare geographic assignment file (`geo.toml`):**

   ```toml
   minimum_jurisdictions = 3

   [[shards]]
   shard_index = 0
   jurisdiction = "IS"   # Iceland
   holder_description = "Trusted contact — no identifying info here"

   [[shards]]
   shard_index = 1
   jurisdiction = "DE"   # Germany
   holder_description = "Trusted contact"

   [[shards]]
   shard_index = 2
   jurisdiction = "BR"   # Brazil
   holder_description = "Trusted contact"

   [[shards]]
   shard_index = 3
   jurisdiction = "IS"
   holder_description = "Second Iceland contact (parity)"

   [[shards]]
   shard_index = 4
   jurisdiction = "TW"   # Taiwan
   holder_description = "Trusted contact (parity)"
   ```

2. **Distribute with canary and geographic manifest:**

   ```bash
   shadowforge embed-distributed \
       --input sensitive_document.txt \
       --covers contact_photos/*.jpg \
       --data-shards 3 \
       --parity-shards 2 \
       --output-archive distribution.zip \
       --key ~/keys/public.key \
       --technique lsb \
       --canary \
       --geo-manifest geo.toml
   ```

   This produces:
   - `distribution.zip` — 5 stego photos, one per contact
   - `geo_manifest.md` — Markdown recovery guide for your editor
   - `canary_shard.jpg` — Keep this. Send it to a honeypot location.
     If it's ever used in a reconstruction attempt, you'll know.

3. **Distribute the stego photos** to your contacts via separate channels.
   Send `geo_manifest.md` to your editor in a sealed envelope or via
   SecureDrop — they hold it as the recovery guide.

4. **Reconstruction** (by the editor or a designated contact):
   - Collect at least 3 photos from any 3 contacts

   - ```bash
     shadowforge extract-distributed \
         --input-archive collected_shards.zip \
         --key ~/keys/secret.key \
         --output recovered_document.txt \
         --technique lsb
     ```

**Legal complexity**: An adversary must simultaneously compel or obtain
cooperation from contacts in at least 3 different jurisdictions. Under
MLAT, this typically takes months. By then, the story is published.

---

## Scenario 4: Source Protection via Time-Lock

**Goal**: A source provides a document that the journalist genuinely cannot
decrypt until a specified date — protecting the source by proving the
journalist had no advance access.

### Source side

```bash
# Lock the document until the agreed publication date
shadowforge time-lock lock \
    --input source_document.txt \
    --unlock-at "2026-09-01T00:00:00Z" \
    --output locked_puzzle.json
```

Send `locked_puzzle.json` to the journalist. The puzzle contains no key
material — it is safe to send via any channel.

### Journalist side

The journalist holds `locked_puzzle.json`. They cannot decrypt it before
September 1, 2026, regardless of what compulsion they face (they simply
don't have the key — the key is derived by completing the sequential
computation, which takes until the specified time even on the best hardware).

```bash
# Before the date — returns nothing
shadowforge time-lock try-unlock --puzzle locked_puzzle.json

# After the date
shadowforge time-lock unlock \
    --puzzle locked_puzzle.json \
    --output decrypted_document.txt
```

> ⚠️ Time-lock puzzles do not provide absolute time guarantees — a highly
> resourced adversary with specialised hardware can potentially solve them
> earlier. They provide practical protection, not cryptographic guarantees.
> For the highest-risk scenarios, use geographic distribution instead of
> (or in addition to) time-locks.

---

## Scenario 5: Zero-Trace Operation at a High-Risk Workstation

**Goal**: Use shadowforge-rs on a compromised or untrusted workstation
(e.g., a hotel business centre, a newsroom under surveillance) with no
traces left on the filesystem.

```bash
# Embed — read cover from stdin, write stego to stdout, no files touched
cat cover_photo.jpg | shadowforge embed \
    --input /dev/stdin \           # payload from stdin
    --cover /dev/stdin \           # cover from stdin (use two separate pipes)
    --technique lsb \
    --key - \                      # key from stdin
    --amnesia > stego_output.jpg

# More practical: pipe everything
shadowforge embed \
    --amnesia \
    --input <(cat payload.txt) \
    --cover <(cat cover.jpg) \
    --key <(cat public.key) \
    --technique lsb > output.jpg
```

With `--amnesia`:

- No temp files created anywhere
- No log output
- Key material zeroed in memory immediately after use
- The only filesystem write is your explicit redirect (`> output.jpg`)

For maximum security: boot from a live USB (Tails), run in `--amnesia` mode,
write only to an encrypted external drive.

---

## General OPSEC Principles

1. **Keys and covers are separate concerns.** Never store a key and its
   corresponding stego cover in the same location.

2. **Short key lifetimes.** Generate fresh keys per communication where
   practical. Long-lived keys are a long-lived attack surface.

3. **Verify before trusting.** Before distributing a stego cover, always
   run `shadowforge extract` to confirm the payload is recoverable.

4. **Dead drop accounts have no identity.** If using dead drop mode, the
   posting account should have zero connection to either party.

5. **The canary is your early warning system.** After every distribution,
   set a calendar reminder to check your canary URL. If it fires, assume
   compromise and rotate.

6. **shadowforge-rs is a layer, not a solution.** Use it alongside Signal
   for real-time communication, Tor for network anonymity, and SecureDrop
   for high-risk initial contact. Steganography hides the existence of
   communication; it does not replace encrypted communication channels.

---

*Last updated: March 2026 | For shadowforge-rs v0.1.0*

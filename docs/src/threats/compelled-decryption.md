# Compelled Decryption

## Threat

Border agents or authorities demand decryption of seized devices and storage media. Refusal may result in legal penalties or worse.

## Countermeasures

### Deniable Steganography

The `DeniableEmbedder` creates dual-payload stego files. Under compulsion, reveal the decoy key — it extracts an innocuous decoy payload. The real payload remains hidden and requires the primary key.

```bash
shadowforge embed --input real-secret.txt --cover photo.png --output stego.png \
  --technique lsb --deniable \
  --key primary.key --decoy-payload shopping-list.txt --decoy-key decoy.key
```

**Under compulsion**: hand over `decoy.key`. The adversary gets the shopping list. They cannot prove a second payload exists.

### Panic Wipe

Emergency secure deletion of all key material. Three-pass overwrite, exits silently with code 0.

This command is hidden from `--help` output to avoid drawing attention.

### Time-Lock Puzzles

Encrypt the payload such that it can't be opened until a sequential computation completes. Even seizing the device doesn't help — the key doesn't exist yet.

```bash
shadowforge time-lock lock --input secret.txt --output locked.bin --duration 86400
```

## Residual Risk

Deniability fails if the adversary obtains both keys. Time-lock puzzles provide practical delay, not a cryptographic hard guarantee (hardware improvements may shorten the delay).

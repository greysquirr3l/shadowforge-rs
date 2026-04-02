# Crossing a Border

## Scenario

You are carrying sensitive material and expect device inspection at a border crossing. Authorities may demand you unlock your device and decrypt files.

## Procedure

### Before Travel

1. **Embed with deniable steganography:**

   ```bash
   shadowforge embed --input real-source-docs.pdf --cover vacation-photo.png \
     --output photo.png --technique lsb --deniable \
     --key primary.key --decoy-payload shopping-list.txt --decoy-key decoy.key
   ```

2. **Memorise** (do not write down) which key is primary and which is decoy.

3. **Store the decoy key** on the device in an obvious location.

4. **Store the primary key** separately — on a remote server, in a password manager accessible only via memorised credentials, or carried on a separate micro SD card.

### At the Border

If compelled to decrypt:

1. Provide the **decoy key**. It produces the shopping list.
2. The adversary sees a plausible explanation and has no evidence of a second payload.

### Emergency

If you believe the device will be seized and forensically examined:

1. Run the panic wipe (this command is hidden from `--help`).
2. The wipe performs 3-pass overwrite of all configured key paths.
3. The command exits silently with code 0 — no visible evidence of the operation.

### After Travel

Retrieve the primary key from your backup location and extract the real payload:

```bash
shadowforge extract --input photo.png --output source-docs.pdf \
  --technique lsb --key primary.key
```

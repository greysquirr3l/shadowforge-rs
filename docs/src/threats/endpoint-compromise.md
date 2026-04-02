# Endpoint Compromise

## Threat

The adversary seizes the device and performs forensic imaging — including swap, temp files, and memory dumps.

## Countermeasures

### Amnesiac Mode

The entire embed/extract pipeline runs through `std::io::pipe()` with zero disk writes. No temporary files, no swap entries.

```bash
cat cover.png | shadowforge embed \
  --input secret.txt --output /dev/stdout --technique lsb --amnesia > stego.png
```

### ZeroizeOnDrop

All structs holding key material or plaintext payloads implement `ZeroizeOnDrop`. When they go out of scope, memory is securely overwritten before deallocation — not left for forensic recovery.

### Constant-Time Comparisons

All cryptographic comparisons use `subtle::ConstantTimeEq` to prevent timing side channels that could leak key material.

## Residual Risk

Cold-boot attacks against RAM and hardware-level memory forensics remain outside the software mitigation scope. Use full-disk encryption and power off devices when not in active use.

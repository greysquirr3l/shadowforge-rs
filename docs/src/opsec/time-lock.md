# Time-Lock Source Protection

## Scenario

A journalist holds material that should only become decryptable after a certain date — for example, to allow a source to relocate before publication.

## Procedure

1. **Embed with a time-lock puzzle:**

   ```bash
   shadowforge time-lock \
     --input story-draft.pdf \
     --duration 72h \
     --output locked-payload.bin
   ```

   This wraps the payload in a Rivest sequential-squaring puzzle that requires approximately 72 hours of continuous CPU work to solve.

2. **Distribute the locked payload** to the publisher or a third party.

3. **After the duration**, the recipient solves the puzzle and recovers the plaintext:

   ```bash
   shadowforge time-lock --unlock \
     --input locked-payload.bin \
     --output story-draft.pdf
   ```

## Key Points

- The puzzle is inherently sequential — parallelism does not speed it up.
- The sender does not need to remain reachable for the recipient to unlock the payload.
- Combine with geographic distribution for layered protection: distribute time-locked shards across jurisdictions.
- Duration estimates are approximate. Calibrate against the target hardware if precision matters.

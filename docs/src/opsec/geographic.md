# Geographic Threshold Distribution

## Scenario

Sensitive material must be split so that no single jurisdiction can compel full recovery. Shards are distributed across multiple countries, requiring cooperation from at least K of N recipients.

## Procedure

1. **Generate a geographic manifest:**

   ```bash
   shadowforge embed distributed \
     --cover images/ --input classified.pdf \
     --technique lsb --redundancy 3 \
     --shards 7 --threshold 4 \
     --output-dir shards/ \
     --manifest geo-manifest.json
   ```

2. **Distribute shards** to recipients in different legal jurisdictions, ensuring no single country holds K or more shards.

3. **Verify threshold.** Confirm that any 4 of the 7 recipients can reassemble the payload, but no 3 or fewer can.

4. **Recovery:**

   ```bash
   shadowforge extract distributed \
     --input-dir collected-shards/ \
     --manifest geo-manifest.json \
     --output recovered.pdf
   ```

## Design Rationale

- Legal cooperation across K jurisdictions is far harder to achieve than a single-country subpoena.
- Reed-Solomon erasure coding ensures that losing up to (N − K) shards does not destroy the payload.
- The manifest itself reveals only shard metadata (indices, checksums), not the payload.

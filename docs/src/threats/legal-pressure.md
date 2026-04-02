# Legal & Jurisdictional Pressure

## Threat

Adversaries use legal instruments across jurisdictions to compel disclosure or seize material. A single-jurisdiction seizure could compromise the entire payload.

## Countermeasures

### Geographic Threshold Distribution

Split the payload into shards distributed across multiple jurisdictions. Require shards from a minimum number of distinct jurisdictions to reconstruct.

```bash
shadowforge embed-distributed \
  --input secret.txt --covers "covers/*.png" \
  --output-archive distributed.zip \
  --technique lsb --geo-manifest jurisdictions.toml
```

No single jurisdiction's legal authority can compel disclosure of enough shards.

### Canary Shards

Inject tripwire shards into the distribution. If a compromised shard is accessed, the canary triggers, alerting the distribution network.

```bash
shadowforge embed-distributed \
  --input secret.txt --covers "covers/*.png" \
  --output-archive distributed.zip \
  --technique lsb --canary
```

## Residual Risk

Coordination between multiple jurisdictions (e.g. MLAT treaties) could theoretically overcome threshold distribution. The minimum-jurisdictions setting should account for known bilateral agreements.

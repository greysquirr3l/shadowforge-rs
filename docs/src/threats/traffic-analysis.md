# Traffic Analysis

## Threat

Adversaries monitor network traffic to identify sender-recipient communication patterns. Even encrypted channels reveal who is talking to whom.

## Countermeasure: Dead Drop Mode

Dead drop mode eliminates direct communication between sender and recipient:

1. The sender embeds the payload into an image using platform-aware encoding.
2. The sender posts the image publicly (social media, image hosting).
3. The recipient downloads the public image and extracts the payload.

No direct network connection between sender and recipient ever occurs.

```bash
shadowforge dead-drop \
  --cover photo.jpg --input secret.txt \
  --platform twitter --output post.jpg
```

## Residual Risk

The adversary could correlate posting timestamps with known source activity. Use Tor/VPN for the upload. The recipient's download is indistinguishable from normal browsing.

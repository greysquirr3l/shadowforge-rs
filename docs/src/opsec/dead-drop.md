# Dead Drop via Public Platform

## Scenario

You need to transfer material to a recipient without any direct communication channel that could be intercepted or logged.

## Procedure

### Sender

1. **Prepare the cover image.** Choose a plausible photo for the target platform.

2. **Encode for the platform:**

   ```bash
   shadowforge dead-drop \
     --cover vacation.jpg --input source-material.pdf \
     --platform twitter --output post.jpg
   ```

3. **Upload** the image to the agreed-upon platform using Tor or a VPN.

4. **Share the manifest** (extraction technique, shard count if distributed) through a separate out-of-band channel (e.g. Signal, in-person meeting).

### Recipient

1. **Download** the image from the public platform.

2. **Extract:**

   ```bash
   shadowforge extract --input post.jpg --output recovered.pdf --technique dct
   ```

## Key Points

- The sender and recipient never directly communicate over the transfer channel.
- The image appears as normal social media content to any observer.
- Platform recompression is accounted for by the survivable encoding.
- Use a fresh account (or throwaway) for the upload to avoid correlation with known identities.

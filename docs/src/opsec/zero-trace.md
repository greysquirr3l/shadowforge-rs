# Zero-Trace Operation

## Scenario

You need to embed or extract material on a machine that may later be seized for forensic analysis. No artifacts — temporary files, swap entries, shell history — should survive the session.

## Procedure

1. **Boot from a live OS** (e.g. Tails) if possible. This eliminates disk writes at the OS level.

2. **Run in amnesiac mode:**

   ```bash
   shadowforge embed \
     --cover photo.png --input payload.bin \
     --technique lsb --amnesiac \
     --output stego.png
   ```

   With `--amnesiac`, shadowforge routes all intermediate data through in-memory pipes (`std::io::pipe()`). No temporary files are created on disk.

3. **Transfer the output** to removable media or a network destination immediately.

4. **Clear the terminal** and wipe shell history before shutting down:

   ```bash
   history -c && history -w
   ```

## Design Rationale

- Amnesiac mode eliminates the primary forensic artifact: temporary files in `/tmp` or the working directory.
- `std::io::pipe()` keeps intermediate buffers in kernel memory, not on the filesystem.
- Key material is zeroed on drop via `ZeroizeOnDrop`.
- Combining amnesiac mode with a live OS provides defense in depth — even if the application leaks something, the OS discards it on shutdown.

## Limitations

- Amnesiac mode does not prevent the OS itself from swapping memory pages to disk. Use a live OS or disable swap.
- If the output file is written to a non-volatile filesystem, the output itself is of course recoverable. Use encrypted removable media or a network transfer.

# Keepsafe Local Recovery

A Windows command-line utility for attempting recovery of media from a **locally extracted Keepsafe iOS app-data folder**. It builds a media manifest from the local Keepsafe database and then decrypts media files using the local `skey.data` file.

> **Status: experimental.** The database reader and recovery flow were validated against one Keepsafe iOS 11.11.1 extraction. Other app versions, extraction tools, storage layouts, and encryption formats have not been independently tested. Recovery is not guaranteed.

This is an independent community project. It is not affiliated with, endorsed by, or supported by Keepsafe.

## What this project does

1. Reads a compatible local Keepsafe database snapshot under `Documents/rdb_backups/`.
2. Reconstructs a CSV manifest with internal media IDs, original filenames, sizes, MIME types, and related metadata.
3. Reads the local `Documents/skey.data` and encrypted files under `Documents/primary/`.
4. Writes recovered copies to a separate output directory and records results in `recovery-log.csv`.

All processing is local. The scripts do not send files, keys, manifests, or telemetry anywhere.

## Important safety notes

- Work from a **copy** of the extracted app-data folder. Keep the original unchanged.
- Never upload or commit `skey.data`, `skey-bak.data`, database files, an actual generated manifest, recovery logs, or recovered photos/videos.
- A generated manifest contains private filenames and metadata. Keep it on your own computer.
- Only use this project to recover media that belongs to you or that you are authorized to recover.
- If the local key material is missing or the backup format is incompatible, this tool cannot recreate it.

## Compatibility and observed format

The current implementation is based on a successful recovery from one Keepsafe iOS 11.11.1 extraction. In that tested sample:

- `skey.data` was 16 bytes and was accepted as an AES-128 key.
- The encrypted media container was observed to contain a one-byte padding-length prefix, a 16-byte IV, and AES-CBC ciphertext.
- The original plaintext length was obtained from the local database metadata; the decrypted buffer was trimmed to that recorded size.
- JPEG, PNG, and MP4 signatures were checked after recovery.

This is an **empirically observed format**, not an official Keepsafe file-format specification. Do not assume it applies to other Keepsafe versions or backup types. The code does not attempt to bypass account security or recover a missing key.

## Requirements

- Windows 10 or Windows 11.
- Python 3.10 or newer (`py` launcher recommended).
- Windows PowerShell 5.1 or newer.
- Python package `msgpack` (installed from `requirements.txt`).
- An extracted Keepsafe app-data folder containing, at minimum:
  - `Documents/skey.data`
  - `Documents/primary/`
  - `Documents/rdb_backups/<timestamp>/*.sst`

The database builder currently supports the LevelDB/RocksDB table formats observed in the tested extraction. If the database layout differs, the builder should stop with an error rather than silently inventing metadata.

## Quick start

### 1. Preserve the backup

Make a second copy of the entire extracted Keepsafe folder. Do not experiment on your only copy.

For example, the extracted root may look like:

```text
D:\Keepsafe-Extracted\
  Documents\
    skey.data
    primary\
    rdb_backups\
      1711936898626\
        *.sst
        MANIFEST-*
  Library\
    Preferences\
      com.keepsafe.KeepSafe.plist
```

The root passed to the commands below is the folder that contains `Documents` (in this example, `D:\Keepsafe-Extracted`). You may also pass the `Documents` folder itself.

### 2. Download this repository

On GitHub, choose **Code → Download ZIP**, then extract the ZIP to a working folder, such as:

```text
%USERPROFILE%\Desktop\keepsafe-local-recovery
```

### 3. Install the one Python dependency

Open PowerShell in the extracted project folder and run:

```powershell
py -m pip install -r requirements.txt
```

### 4. Generate your own manifest

Replace the example path with the location of your own extracted Keepsafe folder:

```powershell
py .\src\build_manifest.py `
  --keepsafe-root "D:\Keepsafe-Extracted" `
  --output "$env:USERPROFILE\Desktop\keepsafe_media_manifest.csv"
```

The builder chooses the newest timestamped snapshot under `Documents/rdb_backups/` that contains `.sst` files. The CSV is personal data; this command writes it to your Desktop, outside the project folder. Keep it local and do not post it in a public issue or discussion. GitHub browser uploads do not apply `.gitignore`, so keeping the manifest outside this project folder is important.

### 5. Recover media into a separate folder

Run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force

.\src\recover_keepsafe.ps1 `
  -KeepsafeRoot "D:\Keepsafe-Extracted" `
  -ManifestPath "$env:USERPROFILE\Desktop\keepsafe_media_manifest.csv" `
  -OutputRoot "$env:USERPROFILE\Desktop\Keepsafe-Recovered"
```

The script reads the key and encrypted media from the extracted folder and writes recovered copies to `Keepsafe-Recovered`. It does not edit the source files. It prefixes each output filename with the internal media ID to avoid accidental overwrites when original filenames repeat.

### 6. Review the recovery log

Open:

```text
%USERPROFILE%\Desktop\Keepsafe-Recovered\recovery-log.csv
```

Possible statuses:

- `RECOVERED_SIGNATURE_VERIFIED`: decryption, recorded size, and a supported media signature matched.
- `RECOVERED_UNVERIFIED`: decryption and size trimming completed, but no known signature check was available for that type.
- `MISSING`: the encrypted media file was not found at the expected location.
- `FAILED`: metadata, file structure, decryption, or signature validation failed.

A matching file signature is a useful sanity check, not a guarantee that every frame or byte of a media file is intact. Open a sample of recovered files and keep the original backup until you have independently checked the results.

## Troubleshooting

### `skey.data` not found

Pass the parent folder that contains `Documents`, or pass `Documents` itself. Confirm that `Documents/skey.data` exists in your extracted copy.

### No `rdb_backups` snapshot found

The current manifest builder expects timestamped database snapshots under `Documents/rdb_backups/`. An extraction with only `Documents/rdb/`, a different database engine, or no `.sst` snapshot files is not currently supported.

### Unsupported SSTable magic or compression

The database format differs from the format observed during development. Do not rename or alter the database files to force compatibility. Open a GitHub issue with only the error text and app-version information; do not attach your backup, key, manifest, or personal media.

### Some media is missing or fails validation

Check that the extracted `Documents/primary/` directory is complete and that the generated manifest came from the same extraction. Keep the log private because it contains original filenames and internal IDs.

## Development

Install dependencies:

```powershell
py -m pip install -r requirements.txt
```

Run the parser tests:

```powershell
py -m unittest discover -s tests -v
```

## Responsible disclosure and issues

Please do not post secrets or personal backup data in Issues. See [SECURITY.md](SECURITY.md) before reporting a security concern or compatibility problem.

## License

MIT. See [LICENSE](LICENSE).

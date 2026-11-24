# Security and privacy

This program handles sensitive personal media and encryption material. Treat the entire extracted Keepsafe folder as private.

## Never publish or attach

- `skey.data` or `skey-bak.data`
- A real `keepsafe_media_manifest.csv`
- `rdb`, `rdb_backup`, `rdb_backups`, `accountlog`, or other extracted database folders
- Recovery logs (they can contain filenames and internal identifiers)
- Recovered photos, videos, or previews
- Full screenshots that expose private filenames, IDs, or media

## Reporting a problem

For a public compatibility issue, share only:

- Keepsafe app version, if known
- Extraction tool and platform, if known
- The command used (remove personal paths)
- The exact non-sensitive error message
- Counts of recovered/missing/failed items, without filenames or IDs

Do not upload the backup or encryption material. If you believe you found a security vulnerability in this project, do not publish exploit details in a public issue; contact the repository maintainer privately using the contact method listed on the repository profile.

## Scope

This project is intended for recovery of the user's own data or data they are explicitly authorized to handle. It does not attempt remote access, account takeover, or cloud-service intrusion.

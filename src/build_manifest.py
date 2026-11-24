#!/usr/bin/env python3
"""Build a Keepsafe media manifest from a compatible extracted iOS app folder.

This intentionally reads the database locally and writes only metadata to CSV.
It does not read, upload, or decrypt media files.
"""
from __future__ import annotations

import argparse
import csv
import pathlib
import struct
import sys
from collections import defaultdict
from typing import Iterable

try:
    import msgpack
except ImportError:  # pragma: no cover - clear installation hint
    print("Missing dependency: msgpack. Install it with: py -m pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(2)

LEVELDB_MAGIC = 0xDB4775248B80FB57
ROCKSDB_MAGIC = 0x88E241B785F4CFF7
PRIMARY_KEY_PREFIX = "tb#primary##k~|"


def read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if pos >= len(buf) or shift > 63:
            raise ValueError("Invalid varint in table block")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, pos
        shift += 7


def snappy_raw_decompress(src: bytes) -> bytes:
    """Small pure-Python decoder for the Snappy raw block format."""
    expected, pos = read_varint(src, 0)
    out = bytearray()
    while pos < len(src) and len(out) < expected:
        tag = src[pos]
        pos += 1
        kind = tag & 0x03
        if kind == 0:  # literal
            length_code = tag >> 2
            if length_code < 60:
                length = length_code + 1
            else:
                extra = length_code - 59
                if extra < 1 or extra > 4 or pos + extra > len(src):
                    raise ValueError("Invalid Snappy literal length")
                length = int.from_bytes(src[pos:pos + extra], "little") + 1
                pos += extra
            if pos + length > len(src):
                raise ValueError("Truncated Snappy literal")
            out.extend(src[pos:pos + length])
            pos += length
            continue

        if kind == 1:  # COPY_1
            if pos >= len(src):
                raise ValueError("Truncated Snappy COPY_1")
            length = 4 + ((tag >> 2) & 0x07)
            offset = ((tag & 0xE0) << 3) | src[pos]
            pos += 1
        elif kind == 2:  # COPY_2
            if pos + 2 > len(src):
                raise ValueError("Truncated Snappy COPY_2")
            length = 1 + (tag >> 2)
            offset = int.from_bytes(src[pos:pos + 2], "little")
            pos += 2
        else:  # COPY_4
            if pos + 4 > len(src):
                raise ValueError("Truncated Snappy COPY_4")
            length = 1 + (tag >> 2)
            offset = int.from_bytes(src[pos:pos + 4], "little")
            pos += 4

        if offset <= 0 or offset > len(out):
            raise ValueError("Invalid Snappy back-reference")
        for _ in range(length):
            out.append(out[-offset])

    if len(out) != expected:
        raise ValueError(f"Snappy output length mismatch ({len(out)} != {expected})")
    return bytes(out)


def decode_block(block_file: bytes, offset: int, size: int) -> bytes:
    end = offset + size
    if offset < 0 or size < 0 or end + 5 > len(block_file):
        raise ValueError("Table block handle points outside the file")
    raw = block_file[offset:end]
    compression = block_file[end]
    if compression == 0:
        return raw
    if compression == 1:
        return snappy_raw_decompress(raw)
    raise ValueError(f"Unsupported table compression type: {compression}")


def parse_block_entries(block: bytes) -> list[tuple[bytes, bytes]]:
    if len(block) < 4:
        raise ValueError("Table data block is too short")
    restart_count = struct.unpack_from("<I", block, len(block) - 4)[0]
    restart_start = len(block) - 4 - restart_count * 4
    if restart_start < 0:
        raise ValueError("Invalid restart array")

    entries: list[tuple[bytes, bytes]] = []
    previous_key = b""
    pos = 0
    while pos < restart_start:
        shared, pos = read_varint(block, pos)
        non_shared, pos = read_varint(block, pos)
        value_length, pos = read_varint(block, pos)
        if shared > len(previous_key) or pos + non_shared + value_length > restart_start:
            raise ValueError("Invalid prefix-compressed table entry")
        key = previous_key[:shared] + block[pos:pos + non_shared]
        pos += non_shared
        value = block[pos:pos + value_length]
        pos += value_length
        entries.append((key, value))
        previous_key = key
    return entries


def read_block_handle(buf: bytes, pos: int) -> tuple[tuple[int, int], int]:
    offset, pos = read_varint(buf, pos)
    size, pos = read_varint(buf, pos)
    return (offset, size), pos


def read_sstable(path: pathlib.Path) -> Iterable[tuple[bytes, bytes]]:
    data = path.read_bytes()
    if len(data) < 53:
        raise ValueError(f"Table is too small: {path.name}")
    magic = int.from_bytes(data[-8:], "little")

    if magic == LEVELDB_MAGIC:
        footer = data[-48:-8]
        first_handle, pos = read_block_handle(footer, 0)
        index_handle, _ = read_block_handle(footer, pos)
    elif magic == ROCKSDB_MAGIC:
        # RocksDB block-based table footer v4: checksum-type byte, two handles,
        # then fixed-width format version and magic. This layout is the one
        # observed in the Keepsafe 11.11.1 backup used to validate this project.
        footer = data[-53:-8]
        first_handle, pos = read_block_handle(footer, 1)
        index_handle, _ = read_block_handle(footer, pos)
    else:
        raise ValueError(f"Unrecognised SSTable magic in {path.name}: 0x{magic:016x}")

    index_block = decode_block(data, *index_handle)
    for _index_key, handle_bytes in parse_block_entries(index_block):
        handle, _ = read_block_handle(handle_bytes, 0)
        data_block = decode_block(data, *handle)
        yield from parse_block_entries(data_block)


def latest_snapshot(documents: pathlib.Path) -> pathlib.Path:
    backups = documents / "rdb_backups"
    if not backups.is_dir():
        raise FileNotFoundError(
            f"Could not find {backups}. This builder currently expects an extracted "
            "Keepsafe backup containing Documents/rdb_backups/<snapshot>/*.sst."
        )
    candidates = []
    for child in backups.iterdir():
        if child.is_dir() and child.name.isdigit() and list(child.glob("*.sst")):
            candidates.append(child)
    if not candidates:
        raise FileNotFoundError("No timestamped rdb_backups snapshot containing .sst files was found.")
    return max(candidates, key=lambda p: int(p.name))


def unpack_record(value: bytes) -> dict:
    obj = msgpack.unpackb(value, raw=False, strict_map_key=False)
    if not isinstance(obj, dict):
        raise ValueError("Database record is not a MessagePack map")
    return obj


def build_rows(snapshot: pathlib.Path) -> tuple[list[dict[str, str]], int, int]:
    # LevelDB internal keys end in an 8-byte little-endian sequence/type tag.
    latest: dict[bytes, tuple[int, int, bytes]] = {}
    table_files = sorted(snapshot.glob("*.sst"))
    if not table_files:
        raise FileNotFoundError(f"No .sst files found in {snapshot}")

    for table in table_files:
        for internal_key, value in read_sstable(table):
            if len(internal_key) < 8:
                continue
            user_key = internal_key[:-8]
            tag = int.from_bytes(internal_key[-8:], "little")
            sequence = tag >> 8
            value_type = tag & 0xFF
            previous = latest.get(user_key)
            if previous is None or (sequence, value_type) >= (previous[0], previous[1]):
                latest[user_key] = (sequence, value_type, value)

    base_records: dict[str, dict] = {}
    detail_records: dict[str, dict] = {}
    for user_key, (_sequence, value_type, value) in latest.items():
        if value_type == 0:  # deletion tombstone
            continue
        try:
            key = user_key.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if not key.startswith(PRIMARY_KEY_PREFIX):
            continue
        identifier = key[len(PRIMARY_KEY_PREFIX):]
        try:
            obj = unpack_record(value)
        except Exception:
            continue
        if identifier.endswith(":100"):
            detail_records[identifier[:-4]] = obj
        else:
            base_records[identifier] = obj

    rows: list[dict[str, str]] = []
    skipped = 0
    for identifier, base_record in sorted(base_records.items()):
        detail_record = detail_records.get(identifier)
        if detail_record is None:
            skipped += 1
            continue
        base_info = base_record.get(3, {}) if isinstance(base_record, dict) else {}
        detail_info = detail_record.get(3, {}) if isinstance(detail_record, dict) else {}
        if not isinstance(base_info, dict) or not isinstance(detail_info, dict):
            skipped += 1
            continue

        file_id = str(base_record.get(1, identifier))
        filename = base_info.get(20)
        original_size = detail_info.get(31)
        mime_type = detail_info.get(10)
        if not file_id or not file_id.isalnum() or len(file_id) < 2:
            skipped += 1
            continue
        if not isinstance(filename, str) or not filename.strip():
            skipped += 1
            continue
        try:
            original_size_int = int(original_size)
        except (TypeError, ValueError):
            skipped += 1
            continue
        if original_size_int <= 0 or not isinstance(mime_type, str):
            skipped += 1
            continue

        rel_dir = pathlib.PurePosixPath("primary") / file_id[:2]
        stem = file_id + " 100"
        rows.append({
            "file_id": file_id,
            "original_filename": filename,
            "original_size": str(original_size_int),
            "mime_type": mime_type,
            "width": str(detail_info.get(34, "")),
            "height": str(detail_info.get(35, "")),
            "sha1": str(detail_info.get(30, "")),
            "source_relative_path": (rel_dir / stem).as_posix(),
            "preview_relative_path": (rel_dir / (stem + ".preview")).as_posix(),
            "thumbnail_relative_path": (rel_dir / (stem + ".thumb")).as_posix(),
            "created_unix": str(base_info.get(21, "")),
            "modified_unix": "",
        })

    return rows, len(base_records), skipped


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a local Keepsafe media manifest from an extracted iOS app folder.")
    parser.add_argument("--keepsafe-root", required=True, help="Folder containing the extracted Documents and Library folders")
    parser.add_argument("--output", default="keepsafe_media_manifest.csv", help="Output CSV path (default: keepsafe_media_manifest.csv)")
    args = parser.parse_args()

    root = pathlib.Path(args.keepsafe_root).expanduser().resolve()
    documents = root if root.name.lower() == "documents" else root / "Documents"
    if not documents.is_dir():
        parser.error(f"Documents folder not found under: {root}")

    snapshot = latest_snapshot(documents)
    try:
        rows, base_count, skipped = build_rows(snapshot)
    except Exception as exc:
        print(f"Could not read the database snapshot: {exc}", file=sys.stderr)
        return 1

    out = pathlib.Path(args.output).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "file_id", "original_filename", "original_size", "mime_type", "width", "height",
        "sha1", "source_relative_path", "preview_relative_path", "thumbnail_relative_path",
        "created_unix", "modified_unix",
    ]
    with out.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print("Manifest generation complete.")
    print(f"Snapshot used: {snapshot.name}")
    print(f"Base media records found: {base_count}")
    print(f"Complete media records written: {len(rows)}")
    print(f"Records skipped (incomplete/unsupported metadata): {skipped}")
    print(f"CSV written to: {out}")
    print("Note: the CSV contains filenames and metadata from this personal backup. Keep it private.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

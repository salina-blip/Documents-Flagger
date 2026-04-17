#!/usr/bin/env python3
"""
Documents-Flagger
Scans Google Drive files/folders for:
  1. Tenant name mentions (38 configured tenants)
  2. Sensitive data — credentials, pricing, PII, competitor intel

Usage examples:
  # Scan by folder path (name-based)
  python main.py

  # Scan specific Drive IDs (files or folders)
  python main.py --id 1n-HEvkK2_ZUdJw... --id 1oodcZQqGQm6L1...

  # List top-level folders to find correct names
  python main.py --list-folders
"""

import sys
import time
import argparse

from config import GOOGLE_DRIVE_FOLDER_PATH
from drive_client import (
    authenticate,
    resolve_folder_path,
    list_files_in_folder,
    download_file,
    list_root_folders,
)
from id_resolver import collect_files_from_ids
from document_extractor import extract_text, SUPPORTED_MIME_TYPES
from scanner import scan_document
from reporter import print_document_report, print_summary, save_json_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan Google Drive files/folders for tenant names and sensitive data."
    )
    parser.add_argument(
        "--json",
        metavar="OUTPUT_PATH",
        default="scan_report.json",
        help="Path to write JSON report (default: scan_report.json)",
    )
    parser.add_argument(
        "--no-json",
        action="store_true",
        help="Skip writing the JSON report",
    )
    parser.add_argument(
        "--folder",
        metavar="PATH",
        default=None,
        help="Drive folder path (slash-separated), e.g. 'Documentation/102 Documents'",
    )
    parser.add_argument(
        "--id",
        metavar="DRIVE_ID",
        action="append",
        dest="ids",
        default=[],
        help="Google Drive file or folder ID to scan (can be repeated for multiple IDs)",
    )
    parser.add_argument(
        "--list-folders",
        action="store_true",
        help="List all top-level folders in your Drive and exit",
    )
    return parser.parse_args()


def scan_files(service, files: list[dict], label: str) -> list:
    results = []
    start_time = time.time()
    total = len(files)

    for idx, file_meta in enumerate(files, 1):
        file_name = file_meta["name"]
        mime_type = file_meta.get("mimeType", "")

        if mime_type not in SUPPORTED_MIME_TYPES:
            print(f"  [{idx}/{total}] SKIPPED (unsupported type '{mime_type}'): {file_name}")
            continue

        print(f"  [{idx}/{total}] Scanning: {file_name}  [{mime_type}]")
        try:
            file_bytes = download_file(service, file_meta["id"], mime_type)
            text = extract_text(file_bytes, mime_type, file_name)
        except Exception as exc:
            text = f"[EXTRACTION ERROR for '{file_name}': {exc}]"

        result = scan_document(file_name, text)
        results.append(result)
        print_document_report(result, idx, total)

    duration = time.time() - start_time
    print_summary(results, label, duration)
    return results


def main() -> None:
    args = parse_args()

    print(f"\n  Documents-Flagger")
    print(f"  Authenticating with Google Drive…")

    try:
        service = authenticate()
    except FileNotFoundError as exc:
        print(f"\n  ERROR: {exc}\n")
        sys.exit(1)

    # --- Debug: list folders ---
    if args.list_folders:
        print(f"  Top-level folders visible to this account:\n")
        for f in list_root_folders(service):
            print(f"    • {f['name']}  (id: {f['id']})")
        print()
        sys.exit(0)

    # --- Mode 1: scan by explicit Drive IDs ---
    if args.ids:
        print(f"  Mode: scan by Drive ID  ({len(args.ids)} ID(s) provided)")
        files = collect_files_from_ids(service, args.ids)
        if not files:
            print(f"\n  No scannable files found for the provided IDs.\n")
            sys.exit(0)
        print(f"  Found {len(files)} file(s). Starting scan…\n")
        results = scan_files(service, files, label="Drive IDs: " + ", ".join(args.ids))
        if not args.no_json and results:
            save_json_report(results, args.json)
        return

    # --- Mode 2: scan by folder path (name-based) ---
    folder_path = args.folder.split("/") if args.folder else GOOGLE_DRIVE_FOLDER_PATH
    folder_display = " / ".join(folder_path)
    print(f"  Mode: scan by folder path")
    print(f"  Target folder : {folder_display}")
    print(f"  Resolving folder path…")

    try:
        folder_id = resolve_folder_path(service, folder_path)
    except FileNotFoundError as exc:
        print(f"\n  ERROR: {exc}\n")
        sys.exit(1)

    print(f"  Listing files…")
    files = list_files_in_folder(service, folder_id)
    if not files:
        print(f"\n  No files found in '{folder_display}'. Nothing to scan.\n")
        sys.exit(0)

    print(f"  Found {len(files)} file(s). Starting scan…\n")
    results = scan_files(service, files, label=folder_display)

    if not args.no_json and results:
        save_json_report(results, args.json)


if __name__ == "__main__":
    main()

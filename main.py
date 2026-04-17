#!/usr/bin/env python3
"""
Documents-Flagger
Scans every file in the Google Drive folder  Documentation/102 Documents  for:
  1. Tenant name mentions (38 configured tenants)
  2. Sensitive data — credentials, pricing, PII, competitor intel
"""

import sys
import time
import argparse

from config import GOOGLE_DRIVE_FOLDER_PATH
from drive_client import authenticate, resolve_folder_path, list_files_in_folder, download_file
from document_extractor import extract_text, SUPPORTED_MIME_TYPES
from scanner import scan_document
from reporter import print_document_report, print_summary, save_json_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan Google Drive '102 Documents' folder for tenant names and sensitive data."
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
        help="Override the Drive folder path as a slash-separated string, e.g. 'Documentation/102 Documents'",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    folder_path = (
        args.folder.split("/") if args.folder else GOOGLE_DRIVE_FOLDER_PATH
    )
    folder_display = " / ".join(folder_path)

    print(f"\n  Documents-Flagger")
    print(f"  Target folder : {folder_display}")
    print(f"  Authenticating with Google Drive…")

    try:
        service = authenticate()
    except FileNotFoundError as exc:
        print(f"\n  ERROR: {exc}\n")
        sys.exit(1)

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

    results = []
    start_time = time.time()

    for idx, file_meta in enumerate(files, 1):
        file_name = file_meta["name"]
        mime_type = file_meta.get("mimeType", "")

        if mime_type not in SUPPORTED_MIME_TYPES:
            print(f"  [{idx}/{len(files)}] SKIPPED (unsupported type '{mime_type}'): {file_name}")
            continue

        print(f"  [{idx}/{len(files)}] Scanning: {file_name}  [{mime_type}]")
        try:
            file_bytes = download_file(service, file_meta["id"], mime_type)
            text = extract_text(file_bytes, mime_type, file_name)
        except Exception as exc:
            text = f"[EXTRACTION ERROR for '{file_name}': {exc}]"

        result = scan_document(file_name, text)
        results.append(result)
        print_document_report(result, idx, len(files))

    duration = time.time() - start_time
    print_summary(results, folder_display, duration)

    if not args.no_json and results:
        save_json_report(results, args.json)


if __name__ == "__main__":
    main()

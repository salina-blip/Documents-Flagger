#!/usr/bin/env python3
"""
Documents-Flagger Web UI
Run:  python app.py
Then open:  http://localhost:5000
"""

import json
import sys
import threading
import os
from flask import Flask, render_template, request, Response, stream_with_context, send_file

from drive_client import authenticate, collect_files_recursive, list_files_in_folder, download_file
from document_extractor import extract_text, SUPPORTED_MIME_TYPES
from scanner import scan_document
from url_parser import extract_drive_id
from reporter import save_json_report

app = Flask(__name__)

# One shared Drive service instance (re-auth if needed)
_service_lock = threading.Lock()
_service = None


def get_service():
    global _service
    with _service_lock:
        if _service is None:
            try:
                _service = authenticate()
            except FileNotFoundError as exc:
                raise RuntimeError(str(exc))
    return _service


def sse_event(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def run_scan(folder_url: str, include_subfolders: bool):
    """Generator that yields SSE events while scanning."""
    drive_id = extract_drive_id(folder_url)
    if not drive_id:
        yield sse_event("error", {"message": "Could not extract a Drive ID from the URL. Please paste a valid Google Drive folder link."})
        return

    try:
        service = get_service()
    except RuntimeError as exc:
        yield sse_event("error", {"message": str(exc)})
        return

    # Determine if it's a folder or a file
    try:
        meta = service.files().get(
            fileId=drive_id,
            fields="id, name, mimeType",
            supportsAllDrives=True,
        ).execute()
    except Exception as exc:
        yield sse_event("error", {"message": f"Could not access Drive ID '{drive_id}': {exc}"})
        return

    is_folder = meta.get("mimeType") == "application/vnd.google-apps.folder"
    folder_name = meta.get("name", drive_id)

    yield sse_event("status", {"message": f"Found: '{folder_name}' ({'folder' if is_folder else 'file'})"})

    if is_folder:
        yield sse_event("status", {"message": f"Listing files{' (including subfolders)' if include_subfolders else ''}…"})
        if include_subfolders:
            files = []
            for item in collect_files_recursive(service, drive_id, yield_status=True):
                if isinstance(item, str):
                    yield sse_event("status", {"message": item})
                else:
                    files.append(item)
        else:
            files = list_files_in_folder(service, drive_id)
    else:
        files = [meta]

    scannable = [f for f in files if f.get("mimeType") in SUPPORTED_MIME_TYPES]
    skipped = len(files) - len(scannable)

    yield sse_event("status", {
        "message": f"Found {len(files)} file(s) — {len(scannable)} scannable, {skipped} skipped (unsupported type)"
    })

    if not scannable:
        yield sse_event("done", {"total": 0, "results": []})
        return

    all_results = []

    for idx, file_meta in enumerate(scannable, 1):
        file_name = file_meta["name"]
        mime_type = file_meta.get("mimeType", "")
        subfolder_path = file_meta.get("subfolder_path", "")

        yield sse_event("progress", {
            "current": idx,
            "total": len(scannable),
            "file": file_name,
            "path": subfolder_path,
        })

        try:
            file_bytes = download_file(service, file_meta["id"], mime_type)
            text = extract_text(file_bytes, mime_type, file_name)
        except Exception as exc:
            text = f"[EXTRACTION ERROR for '{file_name}': {exc}]"

        result = scan_document(file_name, text)

        result_dict = {
            "file_name": file_name,
            "subfolder_path": subfolder_path,
            "overall_risk": result.overall_risk,
            "recommendation": result.recommendation,
            "extraction_error": result.extraction_error,
            "tenant_matches": [
                {
                    "tenant_name": tm.tenant_name,
                    "occurrences": tm.occurrences,
                    "excerpts": tm.excerpts,
                }
                for tm in result.tenant_matches
            ],
            "security_findings": [
                {
                    "category": f.category,
                    "description": f.description,
                    "excerpt": f.excerpt,
                    "severity": f.severity,
                }
                for f in result.security_findings
            ],
        }
        all_results.append(result_dict)
        yield sse_event("result", result_dict)

    # Save JSON report
    try:
        save_json_report(
            [type("R", (), r)() for r in all_results],  # lightweight shim not needed — save raw
            "scan_report.json",
            raw=all_results,
        )
    except Exception:
        pass

    yield sse_event("done", {
        "total": len(all_results),
        "results": all_results,
    })


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan")
def scan():
    folder_url = request.args.get("url", "").strip()
    include_subfolders = request.args.get("subfolders", "false").lower() == "true"

    if not folder_url:
        return Response("data: {\"error\": \"No URL provided\"}\n\n", mimetype="text/event-stream")

    return Response(
        stream_with_context(run_scan(folder_url, include_subfolders)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/download_report")
def download_report():
    report_path = os.path.join(os.path.dirname(__file__), "scan_report.json")
    if not os.path.exists(report_path):
        return "No report available yet. Run a scan first.", 404
    return send_file(report_path, as_attachment=True, download_name="scan_report.json")


if __name__ == "__main__":
    print("\n  Documents-Flagger Web UI")
    print("  Open your browser at:  http://localhost:5000\n")
    # Trigger authentication before first request
    try:
        get_service()
        print("  Google Drive authenticated successfully.\n")
    except RuntimeError as exc:
        print(f"  WARNING: {exc}\n")
    app.run(debug=False, threaded=True, port=5000)

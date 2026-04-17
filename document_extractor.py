import io
import pdfplumber
import docx

SUPPORTED_MIME_TYPES = {
    "application/vnd.google-apps.document",
    "application/vnd.google-apps.spreadsheet",
    "application/vnd.google-apps.presentation",
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/msword",
    "text/plain",
    "text/csv",
}

# Process PDFs in pages-per-batch to avoid OOM on large files
_PDF_BATCH_PAGES = 50
# Cap total extracted text at 5 MB to keep scanning fast
_MAX_TEXT_BYTES = 5 * 1024 * 1024


def extract_text(file_bytes: bytes, mime_type: str, file_name: str = "") -> str:
    try:
        if mime_type == "application/pdf":
            return _extract_pdf(file_bytes, file_name)
        if mime_type in (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/msword",
        ):
            return _extract_docx(file_bytes, file_name)
        # Google Workspace / plain text — already exported as UTF-8 text
        raw = file_bytes.decode("utf-8", errors="replace")
        return _cap(raw, file_name)
    except Exception as exc:
        return f"[EXTRACTION ERROR for '{file_name}': {exc}]"


def _cap(text: str, file_name: str) -> str:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) > _MAX_TEXT_BYTES:
        truncated = encoded[:_MAX_TEXT_BYTES].decode("utf-8", errors="replace")
        return truncated + f"\n\n[NOTE: '{file_name}' was truncated at 5 MB; remaining content not scanned]"
    return text


def _extract_pdf(file_bytes: bytes, file_name: str) -> str:
    parts = []
    total_bytes = 0

    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        total_pages = len(pdf.pages)
        for batch_start in range(0, total_pages, _PDF_BATCH_PAGES):
            batch_end = min(batch_start + _PDF_BATCH_PAGES, total_pages)
            batch_text_parts = []

            for page_num in range(batch_start, batch_end):
                try:
                    page = pdf.pages[page_num]
                    page_text = page.extract_text(x_tolerance=3, y_tolerance=3)
                    if page_text:
                        batch_text_parts.append(page_text)
                except Exception:
                    # Skip unreadable pages silently
                    continue

            chunk = "\n".join(batch_text_parts)
            chunk_bytes = len(chunk.encode("utf-8", errors="replace"))
            total_bytes += chunk_bytes
            parts.append(chunk)

            if total_bytes >= _MAX_TEXT_BYTES:
                parts.append(
                    f"\n\n[NOTE: '{file_name}' is large ({total_pages} pages); "
                    f"scanned pages 1–{batch_end}. Remaining pages not scanned.]"
                )
                break

    return "\n".join(parts)


def _extract_docx(file_bytes: bytes, file_name: str) -> str:
    doc = docx.Document(io.BytesIO(file_bytes))
    parts = []
    total_bytes = 0

    for para in doc.paragraphs:
        if para.text.strip():
            encoded = para.text.encode("utf-8", errors="replace")
            total_bytes += len(encoded)
            parts.append(para.text)
            if total_bytes >= _MAX_TEXT_BYTES:
                parts.append(f"[NOTE: '{file_name}' truncated at 5 MB]")
                return "\n".join(parts)

    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                if cell.text.strip():
                    encoded = cell.text.encode("utf-8", errors="replace")
                    total_bytes += len(encoded)
                    parts.append(cell.text.strip())
                    if total_bytes >= _MAX_TEXT_BYTES:
                        parts.append(f"[NOTE: '{file_name}' truncated at 5 MB]")
                        return "\n".join(parts)

    return "\n".join(parts)

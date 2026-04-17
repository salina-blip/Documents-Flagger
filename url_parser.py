import re

# Matches a Google Drive ID: 25–60 alphanumeric + dash + underscore chars
_ID_RE = re.compile(r'[-\w]{25,60}')

_PATTERNS = [
    # /folders/ID  or  /file/d/ID
    re.compile(r'/(?:folders|file/d)/([-\w]{25,60})'),
    # ?id=ID  or  &id=ID
    re.compile(r'[?&]id=([-\w]{25,60})'),
    # open?id=ID (Drive share links)
    re.compile(r'open\?id=([-\w]{25,60})'),
    # /d/ID/ (Docs/Sheets/Slides edit URLs)
    re.compile(r'/d/([-\w]{25,60})/'),
]


def extract_drive_id(url_or_id: str) -> str | None:
    """
    Extract a Google Drive file/folder ID from any common Drive URL format,
    or return the input as-is if it already looks like a bare ID.
    """
    url_or_id = url_or_id.strip()
    if not url_or_id:
        return None

    # If it's already a bare ID (no slashes, no scheme) return directly
    if _ID_RE.fullmatch(url_or_id):
        return url_or_id

    for pat in _PATTERNS:
        m = pat.search(url_or_id)
        if m:
            return m.group(1)

    return None

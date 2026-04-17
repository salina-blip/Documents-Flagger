import io
from googleapiclient.http import MediaIoBaseDownload

_SHARED_DRIVE_PARAMS = {
    "includeItemsFromAllDrives": True,
    "supportsAllDrives": True,
}


def get_file_metadata(service, file_id: str) -> dict:
    return service.files().get(
        fileId=file_id,
        fields="id, name, mimeType, size",
        **_SHARED_DRIVE_PARAMS,
    ).execute()


def collect_files_from_ids(service, ids: list[str]) -> list[dict]:
    """
    For each ID: if it's a folder, list all files inside it;
    if it's a file, include it directly. Returns a flat list of file metadata dicts
    with an extra 'source_id' key for traceability.
    """
    from drive_client import list_files_in_folder

    all_files = []
    seen = set()

    for drive_id in ids:
        try:
            meta = get_file_metadata(service, drive_id)
        except Exception as exc:
            print(f"  WARNING: Could not access ID '{drive_id}': {exc}")
            continue

        if meta.get("mimeType") == "application/vnd.google-apps.folder":
            print(f"  ID {drive_id} → folder '{meta['name']}' — listing contents…")
            children = list_files_in_folder(service, drive_id)
            for child in children:
                if child["id"] not in seen:
                    child["source_id"] = drive_id
                    child["source_name"] = meta["name"]
                    all_files.append(child)
                    seen.add(child["id"])
        else:
            if meta["id"] not in seen:
                meta["source_id"] = drive_id
                meta["source_name"] = meta["name"]
                all_files.append(meta)
                seen.add(meta["id"])

    return all_files

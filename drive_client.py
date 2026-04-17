import os
import io
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload

from config import SCOPES, TOKEN_FILE, CREDENTIALS_FILE


def authenticate() -> object:
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(CREDENTIALS_FILE):
                raise FileNotFoundError(
                    f"Missing '{CREDENTIALS_FILE}'. Download it from Google Cloud Console "
                    "(APIs & Services → Credentials → OAuth 2.0 Client ID → Download JSON) "
                    "and place it in the project root."
                )
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, "w") as token:
            token.write(creds.to_json())
    return build("drive", "v3", credentials=creds)


def find_folder_id(service, name: str, parent_id: str = None) -> str | None:
    query = f"name='{name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
    if parent_id:
        query += f" and '{parent_id}' in parents"
    results = service.files().list(q=query, fields="files(id, name)").execute()
    files = results.get("files", [])
    return files[0]["id"] if files else None


def resolve_folder_path(service, path: list[str]) -> str:
    parent_id = None
    for folder_name in path:
        folder_id = find_folder_id(service, folder_name, parent_id)
        if not folder_id:
            raise FileNotFoundError(
                f"Folder '{folder_name}' not found"
                + (f" inside parent '{path[path.index(folder_name)-1]}'" if parent_id else "")
                + ". Verify the folder name and your Drive permissions."
            )
        parent_id = folder_id
    return parent_id


def list_files_in_folder(service, folder_id: str) -> list[dict]:
    files = []
    page_token = None
    while True:
        params = {
            "q": f"'{folder_id}' in parents and trashed=false",
            "fields": "nextPageToken, files(id, name, mimeType, size)",
            "pageSize": 100,
        }
        if page_token:
            params["pageToken"] = page_token
        response = service.files().list(**params).execute()
        files.extend(response.get("files", []))
        page_token = response.get("nextPageToken")
        if not page_token:
            break
    return files


def download_file(service, file_id: str, mime_type: str) -> bytes:
    # Google Workspace files must be exported; binary files downloaded directly
    google_export_map = {
        "application/vnd.google-apps.document": "text/plain",
        "application/vnd.google-apps.spreadsheet": "text/csv",
        "application/vnd.google-apps.presentation": "text/plain",
    }
    if mime_type in google_export_map:
        export_mime = google_export_map[mime_type]
        request = service.files().export_media(fileId=file_id, mimeType=export_mime)
    else:
        request = service.files().get_media(fileId=file_id)
    buffer = io.BytesIO()
    downloader = MediaIoBaseDownload(buffer, request)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    return buffer.getvalue()

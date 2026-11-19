# CSV import and export. No UI code, no database code: just turning entries into CSV and back.
import csv
import io
from urllib.parse import urlparse
from core.config import env_int

MAX_IMPORT_MB = env_int("MAX_IMPORT_MB", 8, minimum=1, maximum=10)  # in MB
MAX_IMPORT_BYTES = MAX_IMPORT_MB * 1024 * 1024
MAX_IMPORT_ROWS = env_int("MAX_IMPORT_ROWS", 5000, minimum=1, maximum=5000)     # in rows

EXPORT_COLUMNS = ["name", "url", "username", "password", "notes", "vault"]

# Header names other apps use → our field names (lowercased, spaces and dashes removed)
ALIASES = {
    "title": {"name", "title", "itemname", "loginname"},
    "url": {"url", "uri", "loginuri", "website", "websiteurl", "loginurl", "urls"},
    "username": {"username", "loginusername", "user", "login", "email", "emailaddress"},
    "password": {"password", "loginpassword", "pass"},
    "notes": {"notes", "note", "extra", "comments", "comment"},
}


def _normalize(header: str) -> str:
    return header.strip().lower().replace(" ", "").replace("_", "").replace("-", "")


def entries_to_csv(entries, vault_names: dict[str, str]) -> str:
    # entries: VaultEntry list; vault_names: vault_id → name. Values are written exactly as stored.
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(EXPORT_COLUMNS)
    for e in entries:
        writer.writerow([e.title, e.url or "", e.username or "", e.password or "",
                         e.notes or "", vault_names.get(e.vault_id, "")])
    return out.getvalue()


def _title_from_url(url: str) -> str:
    # "https://mail.google.com/x" → "mail.google.com"
    host = urlparse(url if "://" in url else f"https://{url}").hostname or ""
    return host.removeprefix("www.")


def parse_csv(data: bytes) -> tuple[list[dict], int]:
    # Returns (rows ready to import, number skipped). Raises ValueError for unusable files.
    if len(data) > MAX_IMPORT_BYTES:
        raise ValueError("That file is too large. The limit is 2 MB.")
    try:
        text = data.decode("utf-8-sig")          # utf-8-sig drops Excel's hidden BOM
    except UnicodeDecodeError as e:
        raise ValueError("The file must be a UTF-8 CSV.") from e

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("The file is empty or has no header row.")

    # Match each of our fields to the first header that fits it
    column_for = {}
    for field, names in ALIASES.items():
        for header in reader.fieldnames:
            if header and _normalize(header) in names:
                column_for[field] = header
                break
    if "password" not in column_for and "username" not in column_for:
        raise ValueError("No password or username column found.")

    rows, skipped = [], 0
    for count, raw in enumerate(reader, start=1):
        if count > MAX_IMPORT_ROWS:
            raise ValueError(f"Too many rows. The limit is {MAX_IMPORT_ROWS}.")
        row = {field: (raw.get(header) or "").strip() if field != "password" else (raw.get(header) or "")
               for field, header in column_for.items()}
        for field in ALIASES:
            row.setdefault(field, "")

        if not (row["title"] or row["username"] or row["password"]):
            skipped += 1
            continue
        if not row["title"]:
            row["title"] = _title_from_url(row["url"]) if row["url"] else "Imported login"
        rows.append(row)
    return rows, skipped

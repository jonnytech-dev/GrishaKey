import os
import secrets
import string
from collections import Counter
from datetime import datetime
from pathlib import Path

from fastapi import Request
from fastapi.responses import RedirectResponse
from nicegui import app, run, ui

from starlette.datastructures import MutableHeaders
from starlette.formparsers import MultiPartParser

import api
from core import auth, generator, health, sessions, storage, sharing, transfer, vault


# ========== Config ==========

# Config section:
HOST = os.environ.get("GRISHAKEY_HOST", "127.0.0.1")
PORT = int(os.environ.get("GRISHAKEY_PORT", "9500"))

# The folder this file lives in (the project root, since main.py sits there)
BASE_DIR = Path(__file__).resolve().parent
app.add_static_files("/assets", BASE_DIR / "assets")


# Security headers on every response (pages, API, static files).
# DENY framing stops other sites from loading the app in a hidden frame (clickjacking).
# No strict Content-Security-Policy: NiceGUI needs inline scripts, and a wrong CSP breaks the app.
class SecurityHeaders:
    # Adds security headers to every HTTP response. Pure ASGI (not BaseHTTPMiddleware),
    # so it doesn't interfere with NiceGUI's socket.io connection.
    HEADERS = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in self.HEADERS.items():
                    if name not in headers:
                        headers[name] = value
            await send(message)

        await self.app(scope, receive, send_with_headers)


app.add_middleware(SecurityHeaders)

# Where the database lives
# Docker sets GRISHAKEY_DATA=/data; running locally falls back to a "data" folder here
DATA_DIR = Path(os.environ.get("GRISHAKEY_DATA", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)      # create the folder if it isn't there yet
DB_PATH = DATA_DIR / "grishakey.db"

# Uploads bigger than this get spooled to a temp file on disk (default 1 MB).
# Raised just above the CSV import limit so an imported CSV of passwords stays in memory only.
MultiPartParser.spool_max_size = transfer.MAX_IMPORT_BYTES + 64 * 1024

# Word list for passphrases, loaded once at startup (empty if the file is missing)
WORDLIST = generator.load_wordlist(BASE_DIR / "core" / "wordlists" / "eff_large_wordlist.txt")

# Signs NiceGUI's session cookie so a browser can't forge another user's token
# Comes from the environment, never from code, because this repo goes on GitHub
STORAGE_SECRET = os.environ.get("STORAGE_SECRET")
if not STORAGE_SECRET:
    raise RuntimeError(
        "STORAGE_SECRET is not set. Generate one with:\n"
        '  python -c "import secrets; print(secrets.token_urlsafe(48))"'
    )
# A short secret can be guessed, and then session cookies could be forged
STORAGE_SECRET_MIN_LENGTH = 32
if len(STORAGE_SECRET) < STORAGE_SECRET_MIN_LENGTH:
    raise RuntimeError(
        f"STORAGE_SECRET is too short (at least {STORAGE_SECRET_MIN_LENGTH} characters). Generate one with:\n"
        '  python -c "import secrets; print(secrets.token_urlsafe(48))"'
    )

# Show a searchable list of registered users in share dialogs.
# OFF by default: on a public install it would reveal who has an account.
USER_DIRECTORY = os.environ.get("USER_DIRECTORY", "false").strip().lower() in ("1", "true", "yes", "on")

# ========== Branding ==========

# The app's name in two parts: a plain part and a part drawn in the green gradient.
# Businesses set these in their .env or Docker settings to use their own name.
APP_NAME = os.environ.get("APP_NAME", "Grisha").strip()
APP_NAME_ACCENT = os.environ.get("APP_NAME_ACCENT", "Key").strip()

# Both parts together, for the browser tab and messages ("No GrishaKey account...")
APP_FULL_NAME = APP_NAME + APP_NAME_ACCENT

if not APP_FULL_NAME:
    raise RuntimeError("Set APP_NAME and/or APP_NAME_ACCENT in .env.")
if len(APP_FULL_NAME) > 40:
    raise RuntimeError("APP_NAME and APP_NAME_ACCENT together must be 40 characters or fewer.")

# Required by the LICENSE: this credit must always be visible, exactly as written.
# Do not tie it to APP_NAME or any setting.
POWERED_BY_TEXT = "Powered by GrishaKey by JonnyTech"
POWERED_BY_URL = "https://jonnytech.dev"

# Project links shown with the credit
WEBSITE_URL = "https://grishakey.jonnytech.dev"
GITHUB_URL = "https://github.com/jonnytech-dev/grishakey"

# GitHub "mark" logo (Octicons, MIT license). Uses currentColor, so it follows the text color and hover.
GITHUB_ICON_SVG = (
    '<svg viewBox="0 0 16 16" width="12" height="12" fill="currentColor" aria-hidden="true">'
    '<path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 '
    '0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53'
    '.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 '
    '0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 '
    '1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 '
    '3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 '
    '8c0-4.42-3.58-8-8-8z"/></svg>'
)

# ========== Startup ==========

def setup_database() -> None:
    # Creates every table once, when the app starts
    db_connection = storage.db_connect(DB_PATH)
    try:
        storage.create_tables(db_connection)
    finally:
        db_connection.close()     # always close, even if create_tables fails

setup_database()

# JSON API for the browser extension (/api/v1)
api.setup(DB_PATH)
app.include_router(api.router)

def _brand(size_classes: str):
    # The app name: plain part, then the accent part in the gradient. Either can be empty.
    with ui.row().classes("gap-0 no-wrap items-baseline"):
        if APP_NAME:
            ui.label(APP_NAME).classes(f"{size_classes} font-extrabold tracking-tight text-slate-900")
        if APP_NAME_ACCENT:
            ui.label(APP_NAME_ACCENT).classes(f"{size_classes} font-extrabold tracking-tight gradient-text")

def _credit_links(extra_classes: str = ""):
    # Small "Website · GitHub" links, with the required "Powered by GrishaKey by JonnyTech" under them.
    # The credit is required by the LICENSE. Do not tie it to APP_NAME or any setting.
    with ui.element("div").classes(f"gk-credit {extra_classes}"):
        # with ui.element("div").classes("gk-credit-links"):
        #     with ui.link(target=WEBSITE_URL, new_tab=True).classes("gk-credit-link"):
        #         ui.icon("language").style("font-size: 12px")
        #         ui.label("Website")
        #     ui.label("·").classes("gk-credit-dot")
        #     with ui.link(target=GITHUB_URL, new_tab=True).classes("gk-credit-link"):
        #         ui.html(GITHUB_ICON_SVG, sanitize=False).classes("flex items-center")
        #         ui.label("GitHub")
        # ui.link(POWERED_BY_TEXT, POWERED_BY_URL, new_tab=True).classes("gk-powered")
        ui.label(POWERED_BY_TEXT).classes("gk-powered")

# ========== Actions (run in a background thread, one DB connection each) ==========

def do_login(email: str, password: str, ip_address: str):
    # Opens its own connection, logs in, always closes
    db_connection = storage.db_connect(DB_PATH)
    try:
        return auth.login(db_connection, email, password, ip_address)
    finally:
        db_connection.close()


def do_register(username: str, email: str, password: str, ip_address: str):
    # Opens its own connection, registers, always closes
    db_connection = storage.db_connect(DB_PATH)
    try:
        return auth.register(db_connection, username, email, password, ip_address)
    finally:
        db_connection.close()


def do_create_recovery_code(user_id: str, password: str):
    db_connection = storage.db_connect(DB_PATH)
    try:
        return auth.create_recovery_code(db_connection, user_id, password)
    finally:
        db_connection.close()


def do_recover_account(email: str, code: str, new_password: str, ip_address: str):
    db_connection = storage.db_connect(DB_PATH)
    try:
        new_code = auth.recover_account(db_connection, email, code, new_password, ip_address)
        # The password was reset, so end every session this account had (web and extension)
        user = storage.get_user_by_email(db_connection, email)
        if user is not None:
            sessions.destroy_user(user["user_id"])
        return new_code
    finally:
        db_connection.close()


def load_has_recovery_code(session):
    db_connection = storage.db_connect(DB_PATH)
    try:
        return auth.has_recovery_code(db_connection, session.user_id)
    finally:
        db_connection.close()


def load_user_directory(session):
    db_connection = storage.db_connect(DB_PATH)
    try:
        return sharing.user_directory(db_connection, session)
    finally:
        db_connection.close()


def load_vaults(session):
    # Every vault the user can see, paired with how many entries it has.
    # Counts come from SQL, so no entries are decrypted here.
    db_connection = storage.db_connect(DB_PATH)
    try:
        vaults = sharing.list_vaults(db_connection, session)
        counts = sharing.entry_counts(db_connection, session)
        return [(v, counts.get(v.vault_id, 0)) for v in vaults]
    finally:
        db_connection.close()


def load_passwords_data(session):
    # Everything the Passwords page needs, from ONE connection:
    # vaults (with counts), every readable entry, and who shared each direct share
    db_connection = storage.db_connect(DB_PATH)
    try:
        vaults = sharing.list_vaults(db_connection, session)
        counts = sharing.entry_counts(db_connection, session)
        entries = vault.list_entries(db_connection, session)
        direct_owners = sharing.direct_share_owner_names(db_connection, session)
        return [(v, counts.get(v.vault_id, 0)) for v in vaults], entries, direct_owners
    finally:
        db_connection.close()


def load_dashboard_data(session):
    # Everything the Dashboard needs, from ONE connection.
    # Entries are decrypted here for the health check, then dropped when the page is built.
    db_connection = storage.db_connect(DB_PATH)
    try:
        vaults = sharing.list_vaults(db_connection, session)
        entries = vault.list_entries(db_connection, session)
        trash_count = storage.count_trashed_entries(db_connection, session.user_id)
        return vaults, entries, trash_count
    finally:
        db_connection.close()

def load_entries(session):
    # Every entry the user can read, decrypted (vault members and direct shares)
    db_connection = storage.db_connect(DB_PATH)
    try:
        return vault.list_entries(db_connection, session)
    finally:
        db_connection.close()


def load_entry(session, vault_entry_id: str):
    # One decrypted entry, or None if this user can't reach it
    db_connection = storage.db_connect(DB_PATH)
    try:
        return vault.get_entry(db_connection, session, vault_entry_id)
    finally:
        db_connection.close()


def do_create_vault(session, vault_name: str):
    db_connection = storage.db_connect(DB_PATH)
    try:
        return sharing.create_vault(db_connection, session, vault_name)
    finally:
        db_connection.close()


def do_create_entry(session, vault_id: str, title: str, url: str, username: str, password: str, notes: str):
    db_connection = storage.db_connect(DB_PATH)
    try:
        return vault.add_entry(db_connection, session, vault_id, title, url, username, password, notes)
    finally:
        db_connection.close()


def do_update_entry(session, vault_entry_id: str, title: str, url: str, username: str, password: str, notes: str):
    db_connection = storage.db_connect(DB_PATH)
    try:
        return vault.update_entry(db_connection, session, vault_entry_id, title, url, username, password, notes)
    finally:
        db_connection.close()


def do_delete_entry(session, vault_entry_id: str):
    db_connection = storage.db_connect(DB_PATH)
    try:
        return vault.delete_entry(db_connection, session, vault_entry_id)
    finally:
        db_connection.close()


def do_rename_vault(session, vault_id: str, new_name: str):
    db_connection = storage.db_connect(DB_PATH)
    try:
        sharing.rename_vault(db_connection, session, vault_id, new_name)
    finally:
        db_connection.close()


def do_share_vault(session, vault_id: str, member_email: str, role: str | None = "view"):
    # Adds someone to a vault (sharing.py calls this add_vault_member)
    db_connection = storage.db_connect(DB_PATH)
    try:
        sharing.share_vault(db_connection, session, vault_id, member_email, role)
    finally:
        db_connection.close()


def do_share_entry(session, vault_entry_id: str, member_email: str, role: str = "view"):
    # Shares one entry directly with someone
    db_connection = storage.db_connect(DB_PATH)
    try:
        sharing.share_entry(db_connection, session, vault_entry_id, member_email, role)
    finally:
        db_connection.close()


def load_profile(session):
    db_connection = storage.db_connect(DB_PATH)
    try:
        return auth.get_profile(db_connection, session.user_id)
    finally:
        db_connection.close()


def do_update_profile(session, current_password: str, username: str, email: str):
    db_connection = storage.db_connect(DB_PATH)
    try:
        auth.update_profile(db_connection, session.user_id, current_password, username, email)
    finally:
        db_connection.close()


def do_change_password(session, old_password: str, new_password: str):
    db_connection = storage.db_connect(DB_PATH)
    try:
        auth.change_password(db_connection, session.user_id, old_password, new_password)
        # End every session of this account (other browsers, the extension, and this one),
        # so a stolen session doesn't survive the password change
        sessions.destroy_user(session.user_id)
    finally:
        db_connection.close()


def load_vault_members(session, vault_id: str):
    db_connection = storage.db_connect(DB_PATH)
    try:
        return sharing.list_vault_members(db_connection, session, vault_id)
    finally:
        db_connection.close()


def load_entry_shares(session, vault_entry_id: str):
    db_connection = storage.db_connect(DB_PATH)
    try:
        return sharing.list_entry_shares(db_connection, session, vault_entry_id)
    finally:
        db_connection.close()


def do_remove_vault_member(session, vault_id: str, member_email: str):
    # Removes them AND rotates the vault key (handled inside sharing.py)
    db_connection = storage.db_connect(DB_PATH)
    try:
        sharing.remove_vault_member(db_connection, session, vault_id, member_email)
    finally:
        db_connection.close()


def do_unshare_entry(session, vault_entry_id: str, member_email: str):
    # Removes their direct share AND rotates the entry key (handled inside sharing.py)
    db_connection = storage.db_connect(DB_PATH)
    try:
        sharing.unshare_entry(db_connection, session, vault_entry_id, member_email)
    finally:
        db_connection.close()


def do_trash_entry(session, vault_entry_id: str):
    db_connection = storage.db_connect(DB_PATH)
    try:
        return vault.trash_entry(db_connection, session, vault_entry_id)
    finally:
        db_connection.close()


def load_trash(session):
    db_connection = storage.db_connect(DB_PATH)
    try:
        return vault.list_trash(db_connection, session)
    finally:
        db_connection.close()


def do_restore_entry(session, vault_entry_id: str):
    db_connection = storage.db_connect(DB_PATH)
    try:
        return vault.restore_entry(db_connection, session, vault_entry_id)
    finally:
        db_connection.close()


def do_delete_forever(session, vault_entry_id: str):
    db_connection = storage.db_connect(DB_PATH)
    try:
        return vault.delete_entry_forever(db_connection, session, vault_entry_id)
    finally:
        db_connection.close()


def do_empty_trash(session):
    db_connection = storage.db_connect(DB_PATH)
    try:
        return vault.empty_trash(db_connection, session)
    finally:
        db_connection.close()


def do_export_csv(session, password: str, vault_id: str | None) -> str:
    # Checks the master password, then builds the CSV in memory. vault_id=None → everything.
    db_connection = storage.db_connect(DB_PATH)
    try:
        if not auth.verify_master_password(db_connection, session.user_id, password):
            raise auth.InvalidCredentialsError("Current password is incorrect")
        entries = vault.list_entries(db_connection, session)
        if vault_id:
            entries = [e for e in entries if e.vault_id == vault_id]
        names = {v.vault_id: v.name for v in sharing.list_vaults(db_connection, session)}
        return transfer.entries_to_csv(entries, names)
    finally:
        db_connection.close()


def do_import_rows(session, vault_id: str, rows: list[dict]) -> int:
    # Adds each parsed row to the vault. Returns how many were added.
    db_connection = storage.db_connect(DB_PATH)
    try:
        added = 0
        for row in rows:
            vault.add_entry(db_connection, session, vault_id, row["title"], row["url"],
                            row["username"], row["password"], row["notes"])
            added += 1
        return added
    finally:
        db_connection.close()


# ========== Session helpers ==========

def current_session():
    # The logged-in user's Session, or None
    token = app.storage.user.get("token")
    if token is None:
        return None
    return sessions.get(token)


def logout():
    # Drop the Session from memory and forget the token in the browser
    token = app.storage.user.pop("token", None)
    if token:
        sessions.destroy(token)
    ui.navigate.to("/login")


def show_flash():
    # Shows a message left by the previous page, then removes it so it only shows once
    message = app.storage.user.pop("flash", None)
    if message:
        ui.timer(0.1, lambda: ui.notify(message, type="positive"), once=True)


# Light / Dark / System → what ui.dark_mode expects
THEMES = {"light": False, "dark": True, "auto": None}


def _apply_user_theme():
    # The user's saved theme choice. Stored in app.storage.user, which is fine:
    # it's a preference, not a secret.
    return ui.dark_mode(THEMES.get(app.storage.user.get("theme", "light"), False))


# ========== Small helpers ==========

def generate_password(length: int = 20) -> str:
    # Same secure generator as the Password Generator page, all character types on
    return generator.generate_password(length)


def safe_url(url: str | None) -> str | None:
    # Only real web links become clickable.
    # Blocks things like "javascript:..." that would run code when clicked.
    if url and url.strip().lower().startswith(("http://", "https://")):
        return url.strip()
    return None


def copy_text(text: str, what: str):
    # Copy something to the clipboard and say so
    ui.clipboard.write(text)
    ui.notify(f"{what} copied", type="positive")


def copy_password(password: str):
    # Copy a password, then wipe the clipboard after 30 seconds
    ui.clipboard.write(password)
    ui.notify("Password copied. Clipboard clears in 30 seconds.", type="positive")
    ui.timer(30, lambda: ui.clipboard.write(""), once=True)


# ========== Theme ==========

def _apply_theme():
    # Green brand color, Inter font, background image, glass panels, smooth animations
    ui.colors(primary="#16a34a")
    ui.add_head_html("""
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
        <style>
            .gradient-text {
                background: linear-gradient(90deg, #00994C 0%, #00B570 50%, #00B9BE 100%);
                -webkit-background-clip: text;
                background-clip: text;
                color: transparent;
                padding-bottom: 0.12em;   /* room for the tails of g, j, p, q, y */
                padding-right: 0.04em;    /* tracking-tight can clip the last letter's edge */
            }

            /* Solid green buttons → gradient background */
            /* .q-btn + .gradient-bg = two classes, so it beats Quasar's .bg-primary */
            .q-btn.gradient-bg {
                background: linear-gradient(90deg, #00994C 0%, #00B570 50%, #00B9BE 100%) !important;
                color: #ffffff !important;
            }
            .q-btn.gradient-bg:hover { filter: brightness(1.06); }

            /* Highlighted nav pill → gradient text */
            .q-btn.gradient-text-btn .q-btn__content {
                background: linear-gradient(90deg, #00994C 0%, #00B570 50%, #00B9BE 100%);
                -webkit-background-clip: text;
                background-clip: text;
                -webkit-text-fill-color: transparent;
                color: transparent !important;
            }

            body {
                font-family: 'Inter', sans-serif;
                background:
                    linear-gradient(rgba(248, 250, 252, 0.85), rgba(248, 250, 252, 0.85)),
                    url('/assets/white_background.png') center / cover no-repeat fixed;
            }
            .gk-input .q-field__control { border-radius: 12px; background: #ffffff; }
            .gk-card { border-radius: 24px; box-shadow: 0 24px 60px -24px rgba(15, 23, 42, 0.18); }

            /* ===== Login page layout ===== */
            /* A full-window stage; the logo and form are placed on it by percentage */
            .gk-login-stage { position: relative; width: 100%; min-height: 100vh; }

            /* Logo, top-left */
            .gk-login-logo { position: absolute; left: 3.5vw; top: 3.5vh; }

            /* Form: starts ~57% across, centered vertically, like the image */
            .gk-login-form {
                position: absolute;
                left: 56.5vw;
                top: 50%;
                transform: translateY(-50%);
                width: min(30vw, 500px);
                min-width: 380px;
            }

            /* Taller inputs with a soft white fill */
            .gk-login-input .q-field__control {
                height: 58px;
                border-radius: 12px;
                background: rgba(255, 255, 255, 0.9);
            }
            .gk-login-input .q-field__native { font-size: 16px; }

            /* Register: same spot as the login form, but the page can scroll,
               since five fields are taller than a short window */
            .gk-auth-flow {
                display: flex; align-items: center;
                min-height: 100vh;
                padding: 48px 4vw 96px 56.5vw;
                position: relative;
            }
            .gk-auth-flow .gk-auth-form { width: min(30vw, 500px); min-width: 380px; }

            /* Sign-in pages (login, register, recover): the background follows the theme */
            body.gk-auth-page {
                background: url('/assets/login_background_light.png') center / cover no-repeat fixed;
            }

            /* Small screens: stack everything in the middle instead */
            @media (max-width: 900px) {
                .gk-login-form {
                    left: 50%;
                    transform: translate(-50%, -50%);
                    width: calc(100vw - 32px);
                    min-width: 0;
                }
                .gk-auth-flow { padding: 32px 16px; justify-content: center; }
                .gk-auth-flow .gk-auth-form { width: 100%; min-width: 0; }
            }

            /* ===== Full-screen layout ===== */
            .gk-shell { width: 100%; height: 100vh; }
            .gk-main  { height: 100vh; overflow-y: auto; }
            /* Keep page sections at full height so the main area scrolls instead of squashing them */
            .gk-main > * { flex-shrink: 0; }

            /* Glass sidebar: see-through white + blur of whatever is behind it */
            .gk-sidebar {
                height: 100vh;
                background: rgba(255, 255, 255, 0.45);
                backdrop-filter: blur(20px) saturate(160%);
                -webkit-backdrop-filter: blur(20px) saturate(160%);
                border-right: 1px solid rgba(226, 232, 240, 0.8);
            }

            /* ===== Sidebar items ===== */
            .gk-nav-item {
                display: flex; align-items: center; gap: 14px;
                padding: 10px 14px; border-radius: 12px;
                cursor: pointer; color: #0f172a; font-weight: 600;
            }
            .gk-nav-item:hover { background: rgba(241, 245, 249, 0.8); }
            .gk-nav-active, .gk-nav-active:hover { background: #dcfce7; }
            .gk-sub-item {
                display: flex; align-items: center; gap: 12px;
                padding: 8px 14px 8px 24px; border-radius: 10px;
                cursor: pointer; color: #475569; font-weight: 500;
            }
            .gk-sub-item:hover { background: rgba(241, 245, 249, 0.8); color: #0f172a; }

            /* ===== Vaults list: folds up into the "Vaults" row ===== */
            /* Animating grid rows from 1fr to 0fr slides it to its exact height */
            .gk-collapse {
                display: grid;
                grid-template-rows: 1fr;
                opacity: 1;
                transition: grid-template-rows 0.3s ease, opacity 0.25s ease;
            }
            .gk-collapse > .gk-collapse-inner { overflow: hidden; min-height: 0; }
            .gk-collapse.gk-collapsed { grid-template-rows: 0fr; opacity: 0; }

            /* The arrow turns as the list opens and closes */
            .gk-chevron { transition: transform 0.3s ease; }
            .gk-chevron.gk-rotated { transform: rotate(-90deg); }

            /* ===== Smooth feel on everything you click ===== */
            .q-btn, .gk-nav-item, .gk-sub-item, .gk-vault-card {
                transition: background 0.2s ease, color 0.2s ease, transform 0.15s ease,
                            box-shadow 0.2s ease, border-color 0.2s ease;
            }
            /* A tiny press-in when clicked */
            .q-btn:active, .gk-nav-item:active, .gk-sub-item:active, .gk-vault-card:active {
                transform: scale(0.98);
            }

            /* Page fades and slides in when it loads */
            .nicegui-content { animation: gk-fade-in 0.35s ease both; }
            @keyframes gk-fade-in {
                from { opacity: 0; transform: translateY(6px); }
                to   { opacity: 1; transform: none; }
            }

            /* ===== Search bar key badge ===== */
            .gk-kbd {
                font-size: 12px; font-weight: 600; color: #334155;
                background: #ffffff; border: 1px solid #e2e8f0;
                border-radius: 6px; padding: 2px 8px;
            }

            /* ===== Vault cards: lift a little on hover ===== */
            .gk-vault-card {
                background: rgba(255, 255, 255, 0.75);
                border: 1px solid #e2e8f0; border-radius: 16px;
            }
            .gk-vault-card:hover {
                border-color: #86efac;
                box-shadow: 0 10px 30px -15px rgba(0, 153, 76, 0.35);
                transform: translateY(-2px);
            }

            /* ===== Dialogs ===== */
            .gk-dialog {
                width: min(92vw, 440px);
                max-width: none !important;          /* lift Quasar's default cap */
                border-radius: 20px !important;
                padding: 28px !important;
                box-shadow: 0 30px 80px -20px rgba(15, 23, 42, 0.35) !important;
            }
            .gk-dialog-lg { width: min(94vw, 680px); }   /* for longer forms */

            /* "Add people" row: one line on wide screens, stacks on phones */
            .gk-add-row { display: flex; flex-wrap: nowrap; align-items: flex-start; gap: 8px; width: 100%; }
            @media (max-width: 600px) {
                .gk-add-row { flex-wrap: wrap; }
                .gk-add-row > .gk-add-email { flex: 1 1 100%; }
                .gk-add-row > .gk-add-role { flex: 1 1 auto; width: auto !important; }
                /* Dialogs: a bit less padding so content has room */
                .gk-dialog { padding: 20px !important; width: calc(100vw - 24px); }
            }

            .gk-field-label {
                font-size: 13px; font-weight: 600; color: #334155;
                margin: 16px 0 6px;
            }

            /* ===== Credential page ===== */
            .gk-panel {
                background: rgba(255, 255, 255, 0.8);
                border: 1px solid #e2e8f0;
                border-radius: 20px;
                box-shadow: 0 20px 50px -30px rgba(15, 23, 42, 0.25);
                overflow: hidden;
            }
            .gk-field-row { padding: 16px 20px; border-bottom: 1px solid #f1f5f9; }
            .gk-field-row:last-child { border-bottom: none; }
            .gk-field-row:hover { background: rgba(248, 250, 252, 0.8); }
            .gk-field-key {
                font-size: 11px; font-weight: 700; letter-spacing: 0.06em;
                text-transform: uppercase; color: #94a3b8;
            }
            .gk-mono { font-family: 'JetBrains Mono', ui-monospace, monospace; letter-spacing: 0.02em; }

            /* Big first-letter tile at the top of a credential */
            .gk-letter-tile {
                width: 68px; height: 68px; border-radius: 20px;
                display: flex; align-items: center; justify-content: center;
                font-size: 30px; font-weight: 800; color: #ffffff;
                background: linear-gradient(135deg, #00994C 0%, #00B570 50%, #00B9BE 100%);
                box-shadow: 0 14px 30px -12px rgba(0, 153, 76, 0.55);
            }

            /* Small status pill: "Can edit" / "View only" / "Shared with you" */
            .gk-pill {
                font-size: 12px; font-weight: 600;
                padding: 3px 10px; border-radius: 999px;
                background: #f1f5f9; color: #475569;
            }
            .gk-pill-green { background: #dcfce7; color: #15803d; }

            /* ===== People with access ===== */
            .gk-avatar-sm {
                width: 36px; height: 36px; border-radius: 999px;
                display: flex; align-items: center; justify-content: center;
                font-size: 15px; font-weight: 700; color: #ffffff;
                background: linear-gradient(135deg, #00994C 0%, #00B570 50%, #00B9BE 100%);
                flex-shrink: 0;
            }
            .gk-member-list { max-height: 320px; overflow-y: auto; }
            .gk-member-row { padding: 10px 8px; border-radius: 12px; }
            .gk-member-row:hover { background: rgba(241, 245, 249, 0.8); }

            /* ===== Sidebar sections: "MY VAULTS ─────" ===== */
            .gk-section-header {
                display: flex; align-items: center; gap: 12px;
                padding: 16px 14px 6px 24px;
            }
            .gk-section-label {
                font-size: 11px; font-weight: 700;
                letter-spacing: 0.14em; text-transform: uppercase;
                color: #64748b; white-space: nowrap;
            }
            .gk-section-line { flex: 1; height: 1px; background: #e2e8f0; }

            /* The vault you're currently in */
            .gk-sub-active, .gk-sub-active:hover { background: #e8f9ee; color: #0f172a; }

            /* "+ Create Vault": a full-width sidebar row with a green tint */
            .gk-create-item {
                color: #16a34a !important;
                background: #f0fdf4;
                border: 1px solid #bbf7d0;
                margin: 2px 0 4px;
            }
            .gk-create-item:hover { background: #dcfce7 !important; color: #15803d !important; }

            /* Vault rows nested under "My Vaults" / "Shared with me" sit one step further in */
            .gk-sub-nested { padding-left: 52px !important; font-size: 14px; }

            /* The small arrow at the end of a foldable sidebar row */
            .gk-row-chevron { font-size: 18px; color: #94a3b8; }

            /* ===== Help page ===== */
            .gk-help-chip {
                font-size: 13px; font-weight: 600; color: #15803d;
                background: #f0fdf4; border: 1px solid #bbf7d0;
                padding: 6px 12px; border-radius: 999px; cursor: pointer;
                transition: background 0.2s ease;
            }
            .gk-help-chip:hover { background: #dcfce7; }
            .gk-help-step {
                width: 26px; height: 26px; border-radius: 999px; flex-shrink: 0;
                display: flex; align-items: center; justify-content: center;
                font-size: 13px; font-weight: 700; color: #ffffff;
                background: linear-gradient(135deg, #00994C 0%, #00B570 50%, #00B9BE 100%);
            }
            /* Diagrams sit on a light card so they read well in light and dark mode */
            .gk-diagram {
                background: #ffffff; border: 1px solid #e2e8f0;
                border-radius: 16px; padding: 16px; margin-top: 12px;
                overflow-x: auto;
            }
            .gk-help-section { scroll-margin-top: 24px; }
            .gk-faq .q-item__label { font-weight: 600; }

            /* ===== Recovery code display ===== */
            .gk-recovery-code {
                font-family: 'JetBrains Mono', ui-monospace, monospace;
                font-size: 20px; font-weight: 600; letter-spacing: 0.06em;
                text-align: center; color: #0f172a;
                background: #f0fdf4; border: 1px dashed #86efac;
                border-radius: 14px; padding: 18px 12px; word-break: break-all;
            }

            /* ===== Credit: Website · GitHub, and "Powered by GrishaKey by JonnyTech" ===== */
            .gk-credit { display: flex; flex-direction: column; align-items: center; gap: 2px; }
            .gk-credit-links { display: flex; align-items: center; gap: 8px; }
            .gk-credit-link {
                display: inline-flex; align-items: center; gap: 4px;
                font-size: 11px; font-weight: 600;
                color: #64748b; text-decoration: none;
            }
            .gk-credit-link:hover { color: #15803d; }
            .gk-credit-dot { font-size: 11px; color: #cbd5e1; }
            /* Required by the LICENSE: keep it visible and readable */
            .gk-powered {
                font-size: 11px; font-weight: 500;
                color: #94a3b8; text-decoration: none;
            }
            .gk-powered:hover { color: #15803d; }

            /* Login / register: pinned to the bottom center of the page */
            .gk-credit-bottom {
                position: absolute; left: 50%; bottom: 20px;
                transform: translateX(-50%);
                white-space: nowrap;
            }

            /* ===== Dashboard ===== */
            .gk-dash-hero { position: relative; overflow: hidden; border-radius: 24px; padding: 28px 28px 32px; }
            .gk-dash-hero svg.wave { position: absolute; right: -40px; top: -20px; width: 60%; max-width: 520px; opacity: 0.55; pointer-events: none; }
            .gk-stat {
                --tone-bg: #dcfce7; --tone-fg: #00994C; --tone-soft: rgba(240, 253, 244, 0.9);
                --tone-border: #86efac; --tone-glow: rgba(0, 153, 76, 0.35);
                background: linear-gradient(135deg, var(--tone-soft), rgba(255, 255, 255, 0.75));
                border: 1px solid #e2e8f0; border-radius: 18px;
                padding: 18px; cursor: pointer;
            }
            .gk-stat:hover { border-color: var(--tone-border); box-shadow: 0 10px 30px -15px var(--tone-glow); }
            .gk-stat-icon { width: 48px; height: 48px; border-radius: 14px; display: flex; align-items: center;
                            justify-content: center; background: var(--tone-bg); color: var(--tone-fg); flex-shrink: 0; }
            /* Soft color families for cards and letter tiles (same light tone as the green) */
            .gk-tone-green  { --tone-bg: #dcfce7; --tone-fg: #00994C; --tone-soft: rgba(240, 253, 244, 0.9);
                              --tone-border: #86efac; --tone-glow: rgba(0, 153, 76, 0.35); }
            .gk-tone-blue   { --tone-bg: #dbeafe; --tone-fg: #2563eb; --tone-soft: rgba(239, 246, 255, 0.9);
                              --tone-border: #93c5fd; --tone-glow: rgba(37, 99, 235, 0.3); }
            .gk-tone-violet { --tone-bg: #ede9fe; --tone-fg: #7c3aed; --tone-soft: rgba(245, 243, 255, 0.9);
                              --tone-border: #c4b5fd; --tone-glow: rgba(124, 58, 237, 0.3); }
            .gk-tone-amber  { --tone-bg: #fef3c7; --tone-fg: #d97706; --tone-soft: rgba(255, 251, 235, 0.9);
                              --tone-border: #fcd34d; --tone-glow: rgba(217, 119, 6, 0.3); }
            .gk-tone-rose   { --tone-bg: #ffe4e6; --tone-fg: #e11d48; --tone-soft: rgba(255, 241, 242, 0.9);
                              --tone-border: #fda4af; --tone-glow: rgba(225, 29, 72, 0.3); }
            .gk-tone-teal   { --tone-bg: #ccfbf1; --tone-fg: #0d9488; --tone-soft: rgba(240, 253, 250, 0.9);
                              --tone-border: #5eead4; --tone-glow: rgba(13, 148, 136, 0.3); }
            .gk-tile { background: var(--tone-bg); color: var(--tone-fg); }
            .gk-safety-bar { height: 10px; border-radius: 999px; background: #e2e8f0; overflow: hidden; }
            .gk-safety-bar > div { height: 100%; border-radius: 999px; background: #ef4444; }
            .gk-badge { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; font-weight: 600;
                        padding: 5px 11px; border-radius: 999px; white-space: nowrap; }
            .gk-badge-red { background: #fee2e2; color: #b91c1c; }
            .gk-badge-amber { background: #fef3c7; color: #b45309; }
            /* Password rows with a health problem: colored edge and a faint tint */
            .gk-row-red { border-left: 4px solid #ef4444 !important; background: linear-gradient(90deg, rgba(254, 226, 226, 0.7), rgba(255, 255, 255, 0.75)) !important; }
            .gk-row-amber { border-left: 4px solid #f59e0b !important; background: linear-gradient(90deg, rgba(254, 243, 199, 0.7), rgba(255, 255, 255, 0.75)) !important; }
            .gk-issue-row { padding: 12px 4px; border-top: 1px solid #f1f5f9; cursor: pointer; }
            .gk-issue-row:hover { background: rgba(248, 250, 252, 0.8); }

            /* ===== Mobile layout ===== */
            .gk-mobile-only { display: none; }
            /* Phones: icon groups hide, a ⋮ menu shows instead */
            .gk-show-mobile { display: none !important; }
            .gk-bottom-nav {
                position: fixed; left: 0; right: 0; bottom: 0; z-index: 50;
                display: none; justify-content: space-around; align-items: center;
                padding: 8px 6px calc(8px + env(safe-area-inset-bottom));
                background: rgba(255, 255, 255, 0.92);
                backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
                border-top: 1px solid #e2e8f0;
            }
            .gk-tab { display: flex; flex-direction: column; align-items: center; gap: 2px;
                      font-size: 11px; font-weight: 600; color: #475569;
                      padding: 6px 10px; border-radius: 14px; cursor: pointer; min-width: 56px; }
            .gk-tab-active { background: #dcfce7; color: #15803d; }
            @media (max-width: 767px) {
                .gk-sidebar { display: none !important; }
                .gk-mobile-only { display: flex; }
                .gk-bottom-nav { display: flex; }
                .gk-main { height: 100dvh; padding: 16px 16px 104px !important; }
                .gk-dash-hero { padding: 20px 20px 24px; }
                .gk-dash-hero .text-4xl { font-size: 2rem; line-height: 2.5rem; }
                .gk-issue-chevron { display: none; }
                .gk-badge { font-size: 12px; padding: 4px 9px; gap: 4px; }
                .gk-hide-mobile { display: none !important; }
                .gk-show-mobile { display: inline-flex !important; }
            }

            /* ===== Segmented toggles (same style as the website's view switcher) ===== */
            .gk-segmented.q-btn-group {
                display: inline-flex; flex-wrap: nowrap; gap: 4px; padding: 4px;
                background: #ffffff; border: 1px solid #e2e8f0; border-radius: 16px;
                box-shadow: none; max-width: 100%; overflow-x: auto;
            }
            .gk-segmented .q-btn {
                border-radius: 12px !important; padding: 8px 16px; min-height: 40px;
                font-weight: 600; font-size: 15px; color: #64748b !important;
                background: transparent !important;
                transition: background 0.2s ease, color 0.2s ease, box-shadow 0.2s ease;
            }
            .gk-segmented .q-btn:hover { color: #0f172a !important; }
            .gk-segmented .q-btn:before { box-shadow: none !important; }
            /* The selected option (Quasar gives it the toggle color class) */
            .gk-segmented .q-btn.bg-primary {
                background: linear-gradient(90deg, #00994C 0%, #00B570 50%, #00B9BE 100%) !important;
                color: #ffffff !important;
                box-shadow: 0 10px 22px -12px rgba(0, 153, 76, 0.7);
            }

            /* ===== Dark theme (Quasar adds body--dark when dark mode is on) ===== */
            body.body--dark {
                background:
                    linear-gradient(rgba(2, 6, 23, 0.92), rgba(2, 6, 23, 0.92)),
                    url('/assets/white_background.png') center / cover no-repeat fixed;
                color: #e2e8f0;
            }
            .body--dark .gk-sidebar {
                background: rgba(15, 23, 42, 0.55);
                border-right-color: rgba(51, 65, 85, 0.6);
            }
            .body--dark .gk-nav-item { color: #e2e8f0; }
            .body--dark .gk-nav-item:hover,
            .body--dark .gk-sub-item:hover { background: rgba(30, 41, 59, 0.8); }
            .body--dark .gk-nav-active,
            .body--dark .gk-nav-active:hover { background: rgba(22, 163, 74, 0.18); }
            .body--dark .gk-sub-item { color: #94a3b8; }
            .body--dark .gk-sub-item:hover { color: #f1f5f9; }
            .body--dark .gk-section-label { color: #94a3b8; }
            .body--dark .gk-section-line { background: #1e293b; }
            .body--dark .gk-sub-active,
            .body--dark .gk-sub-active:hover { background: rgba(22, 163, 74, 0.18); color: #f1f5f9; }
            .body--dark .gk-create-item {
                color: #4ade80 !important;
                background: rgba(22, 163, 74, 0.12);
                border-color: rgba(74, 222, 128, 0.35);
            }
            .body--dark .gk-create-item:hover { background: rgba(22, 163, 74, 0.22) !important; }
            .body--dark .gk-row-chevron { color: #64748b; }
            .body--dark .gk-help-chip {
                color: #4ade80; background: rgba(22, 163, 74, 0.12);
                border-color: rgba(74, 222, 128, 0.35);
            }
            .body--dark .gk-help-chip:hover { background: rgba(22, 163, 74, 0.22); }
            .body--dark .gk-diagram { background: #f8fafc; border-color: #334155; }
            .body--dark .gk-recovery-code {
                color: #f1f5f9; background: rgba(22, 163, 74, 0.12); border-color: rgba(74, 222, 128, 0.45);
            }
            body.body--dark.gk-auth-page {
                background: url('/assets/login_background_dark.png') center / cover no-repeat fixed;
            }
            .body--dark .gk-login-input .q-field__control { background: rgba(15, 23, 42, 0.85); }

            .body--dark .gk-vault-card,
            .body--dark .gk-panel { background: rgba(15, 23, 42, 0.7); border-color: #1e293b; }
            .body--dark .gk-field-row { border-bottom-color: #1e293b; }
            .body--dark .gk-field-row:hover { background: rgba(30, 41, 59, 0.6); }
            .body--dark .gk-member-row:hover { background: rgba(30, 41, 59, 0.6); }

            .body--dark .gk-input .q-field__control { background: #0f172a; }
            .body--dark .gk-dialog { background: #0f172a !important; }
            .body--dark .gk-field-label { color: #cbd5e1; }
            .body--dark .gk-kbd { background: #0f172a; border-color: #334155; color: #cbd5e1; }
            .body--dark .gk-pill { background: #1e293b; color: #cbd5e1; }
            .body--dark .gk-pill-green { background: rgba(22, 163, 74, 0.2); color: #4ade80; }
            .body--dark .gk-stat { background: linear-gradient(135deg, var(--tone-soft), rgba(15, 23, 42, 0.7)); border-color: #1e293b; }
            .body--dark .gk-stat,
            .body--dark .gk-tone-green  { --tone-bg: rgba(22, 163, 74, 0.18); --tone-fg: #4ade80; --tone-soft: rgba(22, 163, 74, 0.08); }
            .body--dark .gk-tone-blue   { --tone-bg: rgba(59, 130, 246, 0.18); --tone-fg: #93c5fd; --tone-soft: rgba(59, 130, 246, 0.08); }
            .body--dark .gk-tone-violet { --tone-bg: rgba(139, 92, 246, 0.18); --tone-fg: #c4b5fd; --tone-soft: rgba(139, 92, 246, 0.08); }
            .body--dark .gk-tone-amber  { --tone-bg: rgba(245, 158, 11, 0.18); --tone-fg: #fcd34d; --tone-soft: rgba(245, 158, 11, 0.08); }
            .body--dark .gk-tone-rose   { --tone-bg: rgba(244, 63, 94, 0.18); --tone-fg: #fda4af; --tone-soft: rgba(244, 63, 94, 0.08); }
            .body--dark .gk-tone-teal   { --tone-bg: rgba(20, 184, 166, 0.18); --tone-fg: #5eead4; --tone-soft: rgba(20, 184, 166, 0.08); }
            .body--dark .gk-safety-bar { background: #1e293b; }
            .body--dark .gk-badge-red { background: rgba(239, 68, 68, 0.15); color: #fca5a5; }
            .body--dark .gk-badge-amber { background: rgba(245, 158, 11, 0.15); color: #fcd34d; }
            .body--dark .gk-row-red { background: linear-gradient(90deg, rgba(239, 68, 68, 0.14), rgba(15, 23, 42, 0.7)) !important; }
            .body--dark .gk-row-amber { background: linear-gradient(90deg, rgba(245, 158, 11, 0.14), rgba(15, 23, 42, 0.7)) !important; }
            .body--dark .gk-issue-row { border-top-color: #1e293b; }
            .body--dark .gk-issue-row:hover { background: rgba(30, 41, 59, 0.6); }
            .body--dark .gk-bottom-nav { background: rgba(15, 23, 42, 0.92); border-top-color: #1e293b; }
            .body--dark .gk-tab { color: #94a3b8; }
            .body--dark .gk-tab-active { background: rgba(22, 163, 74, 0.18); color: #4ade80; }
            .body--dark .gk-segmented.q-btn-group { background: #0f172a; border-color: #1e293b; }
            .body--dark .gk-segmented .q-btn { color: #94a3b8 !important; }
            .body--dark .gk-segmented .q-btn:hover { color: #f1f5f9 !important; }
            .body--dark .gk-segmented .q-btn.bg-primary { color: #ffffff !important; }

            /* Text colors written for light mode, flipped for dark */
            .body--dark .text-slate-900 { color: #f1f5f9 !important; }
            .body--dark .text-slate-800,
            .body--dark .text-slate-700 { color: #e2e8f0 !important; }
            .body--dark .text-slate-600,
            .body--dark .text-slate-500 { color: #94a3b8 !important; }
            .body--dark .text-slate-400 { color: #64748b !important; }
            .body--dark .bg-green-50 { background-color: rgba(22, 163, 74, 0.15) !important; }
            .body--dark .bg-slate-200 { background-color: #1e293b !important; }
            .body--dark .bg-slate-100 { background-color: #1e293b !important; }
            .body--dark .gk-credit-link { color: #94a3b8; }
            .body--dark .gk-credit-link:hover { color: #4ade80; }
            .body--dark .gk-credit-dot { color: #475569; }
            .body--dark .gk-powered { color: #64748b; }
            .body--dark .gk-powered:hover { color: #4ade80; }
        </style>
    """)


# ========== Layout ==========

def _section_header(text: str):
    # Small spaced caps label with a thin line filling the rest of the row: "MY VAULTS ─────"
    with ui.row().classes("gk-section-header w-full no-wrap"):
        ui.label(text).classes("gk-section-label")
        ui.element("div").classes("gk-section-line")


def _sidebar_is_open(key: str) -> bool:
    # Remembered open/closed state for a sidebar section (default: open)
    return app.storage.user.get(f"sidebar_{key}", True)


def _set_sidebar_open(key: str, value: bool):
    app.storage.user[f"sidebar_{key}"] = value


def _collapsible_row(key: str, icon: str, title: str):
    # A sidebar row like "All vaults", with an arrow that folds the list under it.
    # Returns the inner column; use it with "with" to fill the list.
    is_open = _sidebar_is_open(key)

    with ui.row().classes("gk-sub-item w-full no-wrap") as header:
        ui.icon(icon).classes("text-lg")
        ui.label(title).classes("flex-1")
        chevron = ui.icon("expand_more").classes("gk-row-chevron gk-chevron" + ("" if is_open else " gk-rotated"))

    # Same fold-up animation as the Vaults section (outer box animates, inner box holds the items)
    with ui.element("div").classes("gk-collapse w-full" + ("" if is_open else " gk-collapsed")) as body:
        inner = ui.column().classes("gk-collapse-inner w-full gap-0")

    def toggle():
        now_open = not _sidebar_is_open(key)
        _set_sidebar_open(key, now_open)
        if now_open:
            body.classes(remove="gk-collapsed")
            chevron.classes(remove="gk-rotated")
        else:
            body.classes(add="gk-collapsed")
            chevron.classes(add="gk-rotated")

    header.on("click", toggle)
    return inner


def _app_shell(vaults, on_create_vault, on_search=None, search_placeholder="Search vaults...",
               active="vaults", show_search=True, active_vault_id=None):
    # Full-screen sidebar + main area for logged-in pages. Returns the main area for page content.

    # NiceGUI pads every page by default; remove it so the app fills the window
    ui.query(".nicegui-content").classes("p-0 gap-0")

    with ui.row().classes("gk-shell no-wrap items-stretch gap-0"):

        # ===== Sidebar (glass) =====
        with ui.column().classes("gk-sidebar w-64 shrink-0 p-5 gap-1"):

            # Logo: "Grisha" dark, "Key" in the gradient
            with ui.row().classes("items-center gap-2 no-wrap px-2 cursor-pointer") \
                    .on("click", lambda: ui.navigate.to("/")):
                _brand("text-2xl")

            ui.element("div").classes("w-full h-px bg-slate-200 my-3")

            # Dashboard: the overview page
            dash_classes = "gk-nav-item w-full no-wrap" + (" gk-nav-active" if active == "dashboard" else "")
            with ui.row().classes(dash_classes).on("click", lambda: ui.navigate.to("/")):
                ui.icon("o_dashboard").classes("text-xl")
                ui.label("Dashboard")

            # Vaults row: click to fold the whole vault section (remembered between pages)
            vaults_open = _sidebar_is_open("vaults")

            def toggle_vaults():
                now_open = not _sidebar_is_open("vaults")
                _set_sidebar_open("vaults", now_open)
                if now_open:
                    vault_list.classes(remove="gk-collapsed")
                    chevron.classes(remove="gk-rotated")
                else:
                    vault_list.classes(add="gk-collapsed")
                    chevron.classes(add="gk-rotated")

            vaults_classes = "gk-nav-item w-full no-wrap"
            with ui.row().classes(vaults_classes).on("click", toggle_vaults):
                ui.icon("sym_o_lock").classes("text-xl")
                ui.label("Vaults").classes("flex-1")
                chevron = ui.icon("expand_more").classes("text-xl gk-chevron" + ("" if vaults_open else " gk-rotated"))

            # ========== Vaults NavBar Section ==========
            # Split once: vaults you own, and vaults shared with you
            my_vaults = [v for v, _count in vaults if v.is_owner]
            shared_vaults = [v for v, _count in vaults if not v.is_owner]

            def vault_link(v):
                # One nested vault row; the vault you're in gets a soft green highlight
                classes = "gk-sub-item gk-sub-nested w-full no-wrap" + (
                    " gk-sub-active" if v.vault_id == active_vault_id else ""
                )
                with ui.row().classes(classes) \
                        .on("click", lambda vid=v.vault_id: ui.navigate.to(f"/vault/{vid}")):
                    ui.icon("o_lock").classes("text-base")
                    ui.label(v.name).classes("truncate")

            # The whole vault section (outer box animates, inner box holds the items)
            with ui.element("div").classes("gk-collapse w-full" + ("" if vaults_open else " gk-collapsed")) as vault_list:
                with ui.column().classes("gk-collapse-inner w-full gap-0"):

                    # 1. Create Vault: first, same width as the rows below, green tint
                    # with ui.row().classes("gk-sub-item gk-create-item w-full no-wrap").on("click", on_create_vault):
                    #     ui.icon("add").classes("text-lg")
                    #     ui.label("Create Vault")

                    # 2. All vaults: back to the grid (not everyone knows the logo is a link)
                    all_classes = "gk-sub-item w-full no-wrap" + (
                        " gk-nav-active" if active == "vaults" and active_vault_id is None else ""
                    )
                    with ui.row().classes(all_classes).on("click", lambda: ui.navigate.to("/vaults")):
                        ui.icon("o_grid_view").classes("text-lg")
                        ui.label("All vaults")

                    # 3. My Vaults: a row with its own arrow, folding the vaults you own
                    with _collapsible_row("my", "o_person", "My Vaults"):
                        for v in my_vaults:
                            vault_link(v)

                    # 4. Shared with me: same, only if something is shared
                    if shared_vaults:
                        with _collapsible_row("shared", "o_group", "Shared with me"):
                            for v in shared_vaults:
                                vault_link(v)
            # ====================================

            # ui.element("div").classes("w-full h-px bg-slate-200 my-3")

            # Passwords: every entry in one list, on its own page
            passwords_classes = "gk-nav-item w-full no-wrap" + (" gk-nav-active" if active == "passwords" else "")
            with ui.row().classes(passwords_classes).on("click", lambda: ui.navigate.to("/passwords")):
                ui.icon("key").classes("text-xl")
                ui.label("Passwords")

            # Trash: entries waiting to be restored or deleted for good
            trash_classes = "gk-nav-item w-full no-wrap" + (" gk-nav-active" if active == "trash" else "")
            with ui.row().classes(trash_classes).on("click", lambda: ui.navigate.to("/trash")):
                ui.icon("delete_outline").classes("text-xl")
                ui.label("Trash")

            settings_classes = "gk-nav-item w-full no-wrap" + (" gk-nav-active" if active == "settings" else "")
            with ui.row().classes(settings_classes).on("click", lambda: ui.navigate.to("/settings")):
                ui.icon("settings").classes("text-xl")
                ui.label("Settings")

            # Help: short guides and answers
            help_classes = "gk-nav-item w-full no-wrap" + (" gk-nav-active" if active == "help" else "")
            with ui.row().classes(help_classes).on("click", lambda: ui.navigate.to("/help")):
                ui.icon("help_outline").classes("text-xl")
                ui.label("Help")

            ui.space()     # pushes Settings to the bottom

            # Password Generator: pinned to the bottom of the sidebar
            generator_classes = "gk-nav-item w-full no-wrap" + (
                " gk-nav-active" if active == "generator" else ""
            )
            with ui.row().classes(generator_classes).on("click", lambda: ui.navigate.to("/generator")):
                ui.icon("password").classes("text-xl")
                ui.label("Password Generator")

            _credit_links("w-full pt-3")

        # ===== Main area (scrolls on its own) =====
        with ui.column().classes("gk-main flex-1 min-w-0 p-6 md:p-10 gap-0") as main_area:

            # Phone-only header: the app name, centered
            with ui.row().classes("gk-mobile-only w-full justify-center mb-4"):
                _brand("text-2xl")

            # Search across the top (left out on pages that don't need it, like Settings)
            if show_search:
                search = ui.input(
                    placeholder=search_placeholder,
                    on_change=(lambda e: on_search(e.value or "")) if on_search else None,
                ).props("outlined dense clearable").classes("gk-input w-full max-w-xl")
                with search.add_slot("prepend"):
                    ui.icon("search").classes("text-slate-500")
                with search.add_slot("append"):
                    ui.label("Ctrl + K").classes("gk-kbd")

    # ===== Phone-only bottom tab bar =====
    with ui.dialog().props("position=bottom") as more_sheet, ui.card().classes("w-full gap-0 p-4").style("border-radius: 20px 20px 0 0"):
        for icon, label, action in [
            ("add", "Create Vault", lambda: (more_sheet.close(), on_create_vault())),
            ("password", "Password Generator", lambda: ui.navigate.to("/generator")),
            ("settings", "Settings", lambda: ui.navigate.to("/settings")),
            ("help_outline", "Help", lambda: ui.navigate.to("/help")),
        ]:
            with ui.row().classes("gk-nav-item w-full no-wrap").on("click", action):
                ui.icon(icon).classes("text-xl")
                ui.label(label)
        _credit_links("w-full pt-4")

    tab_items = [
        ("dashboard", "o_dashboard", "Dashboard", lambda: ui.navigate.to("/")),
        ("vaults", "o_lock", "Vaults", lambda: ui.navigate.to("/vaults")),
        ("passwords", "key", "Passwords", lambda: ui.navigate.to("/passwords")),
        ("trash", "delete_outline", "Trash", lambda: ui.navigate.to("/trash")),
        ("more", "more_horiz", "More", more_sheet.open),
    ]
    with ui.element("nav").classes("gk-bottom-nav"):
        for key, icon, label, action in tab_items:
            is_active = key == active or (key == "more" and active in ("generator", "settings", "help"))
            with ui.element("div").classes("gk-tab" + (" gk-tab-active" if is_active else "")).on("click", action):
                ui.icon(icon).classes("text-2xl")
                ui.label(label)

    return main_area


def _mobile_credit():
    # Phone-only credit at the end of a page (the sidebar that shows it is hidden on phones)
    with ui.element("div").classes("gk-mobile-only w-full justify-center mt-10"):
        _credit_links()


# ========== Dialog building blocks ==========

def _dialog_header(icon: str, title: str, subtitle: str, tone: str = "green"):
    # Icon badge + title + one line of explanation
    badge, color = ("bg-red-50", "#dc2626") if tone == "red" else ("bg-green-50", "#00994C")
    with ui.row().classes("items-center gap-3 no-wrap"):
        with ui.element("div").classes(f"rounded-xl p-2.5 {badge} flex"):
            ui.icon(icon).classes("text-2xl").style(f"color: {color}")
        with ui.column().classes("gap-0 min-w-0"):
            ui.label(title).classes("text-lg font-bold text-slate-900 break-words")
            ui.label(subtitle).classes("text-sm text-slate-500 break-words")


def _field_label(text: str):
    # Small bold label that sits above an input
    ui.label(text).classes("gk-field-label")


def _dialog_footer(dialog, submit_text: str, on_submit, danger: bool = False):
    # Cancel next to the main action, both aligned right
    with ui.row().classes("w-full justify-end gap-2 mt-7"):
        ui.button("Cancel", on_click=dialog.close).props("flat no-caps color=grey-8").classes("rounded-lg")
        if danger:
            ui.button(submit_text, on_click=on_submit) \
                .props("unelevated no-caps color=negative").classes("rounded-lg px-5 font-semibold")
        else:
            ui.button(submit_text, on_click=on_submit) \
                .props("unelevated no-caps").classes("rounded-lg px-5 font-semibold gradient-bg")


def _dialog():
    # A popup that only closes from its own buttons.
    # Clicking outside or pressing Esc does nothing, so typed info isn't lost.
    return ui.dialog().props("persistent")


def _recovery_file_text(email: str, code: str) -> str:
    # Contents of the downloadable .txt file
    return (
        f"{APP_FULL_NAME} recovery code\n\n"
        f"Account: {email}\n"
        f"Recovery code: {code}\n"
        f"Created: {datetime.now().strftime('%Y-%m-%d')}\n\n"
        f"Use this code on the sign-in page (\"Forgot your password?\") to reset your master password.\n"
        f"Anyone with this code and your email can reset your password. Keep it offline and private.\n"
        f"Creating a new code in Settings makes this one stop working.\n"
    )


def _open_recovery_code_dialog(code: str, email: str, on_done):
    # Shows a recovery code ONCE. The user must confirm they saved it before continuing.
    with _dialog() as dialog, ui.card().classes("gk-dialog gap-0"):
        _dialog_header("key", "Save your recovery code",
                       "If you forget your master password, this code is the only way back in.")

        ui.label(code).classes("gk-recovery-code mt-5")

        def copy_code():
            ui.clipboard.write(code)
            ui.notify("Recovery code copied", type="positive")

        def download_code():
            filename = f"{APP_FULL_NAME}-recovery-code.txt"
            ui.download.content(_recovery_file_text(email, code), filename)

        with ui.row().classes("w-full gap-2 mt-4 no-wrap"):
            ui.button("Copy", icon="content_copy", on_click=copy_code) \
                .props("outline no-caps color=grey-8").classes("rounded-lg flex-1")
            ui.button("Download", icon="download", on_click=download_code) \
                .props("outline no-caps color=grey-8").classes("rounded-lg flex-1")

        ui.label("We never store this code, so we can't show it again. Keep it somewhere safe and offline.") \
            .classes("text-sm text-slate-600 mt-4")

        saved = ui.checkbox("I saved my recovery code").props("color=green-7").classes("mt-3")

        def finish():
            dialog.close()
            on_done()

        with ui.row().classes("w-full justify-end mt-5"):
            ui.button("Continue", on_click=finish) \
                .props("unelevated no-caps").classes("rounded-lg px-5 font-semibold gradient-bg") \
                .bind_enabled_from(saved, "value")
    dialog.open()


def _open_confirm_dialog(title: str, message: str, confirm_text: str, on_confirm):
    # "Are you sure?" popup in red. on_confirm is an async function that runs on Confirm.
    with _dialog() as dialog, ui.card().classes("gk-dialog gap-0"):
        _dialog_header("warning_amber", title, message, tone="red")

        async def submit():
            dialog.close()
            await on_confirm()

        _dialog_footer(dialog, confirm_text, submit, danger=True)
    dialog.open()


def _member_row(member, on_remove=None):
    # One person in a "people with access" list. on_remove=None hides the X.
    with ui.row().classes("gk-member-row w-full items-center no-wrap gap-3"):
        ui.label((member.username[:1] or "?").upper()).classes("gk-avatar-sm")
        with ui.column().classes("gap-0 flex-1 min-w-0"):
            ui.label(member.username).classes("font-semibold text-slate-900 truncate")
            ui.label(member.email).classes("text-sm text-slate-500 truncate")
        if member.is_owner:
            ui.label("Owner").classes("gk-pill gk-pill-green")
        else:
            ui.label("Can edit" if member.role == "edit" else "Can view").classes("gk-pill")
        if on_remove:
            ui.button(icon="close", on_click=on_remove) \
                .props("flat round dense color=grey-7").tooltip("Remove access")
        else:
            ui.element("div").style("width: 32px")     # keeps rows lined up when there's no X


def _directory_options(directory, exclude_emails) -> dict[str, str]:
    # email → "name · email", leaving out people who already have access
    return {email: f"{username} · {email}" for username, email in directory if email not in exclude_emails}


def _person_input(directory):
    # The "who to add" box: a searchable user list when USER_DIRECTORY is on, a plain email box otherwise.
    # Either way, .value is the email to share with.
    if USER_DIRECTORY:
        return ui.select(_directory_options(directory, set()), with_input=True, clearable=True,
                         label="Search people") \
            .props("outlined dense use-chips=false").classes("gk-input flex-1")
    return ui.input(placeholder="Email address").props("outlined dense").classes("gk-input flex-1")


def _open_manage_vault_sharing(session, vault_id: str, vault_name: str):
    # Add people to a vault, see who has access, and remove them (owner only)
    directory = load_user_directory(session) if USER_DIRECTORY else []
    has_access = {"emails": set()}      # filled by member_list, used to hide people already added
    with _dialog() as dialog, ui.card().classes("gk-dialog gk-dialog-lg gap-0"):
        _dialog_header("group_add", "Share vault", f'Choose who can open "{vault_name}".')

        @ui.refreshable
        def member_list():
            try:
                members = load_vault_members(session, vault_id)
            except PermissionError:
                ui.label("Only the vault owner can manage sharing.").classes("text-slate-500")
                return
            has_access["emails"] = {m.email for m in members}
            if USER_DIRECTORY:
                email.set_options(_directory_options(directory, has_access["emails"]))
            with ui.column().classes("gk-member-list w-full gap-0"):
                for m in members:
                    _member_row(m, None if m.is_owner else (lambda m=m: confirm_remove(m)))

        async def add():
            try:
                await run.io_bound(do_share_vault, session, vault_id, email.value or "", role.value)
            except LookupError:
                ui.notify(f"No {APP_FULL_NAME} account uses that email.", type="negative")
                return
            except (ValueError, PermissionError) as e:
                ui.notify(str(e), type="negative")
                return
            added = (email.value or "").lower().strip()
            ui.notify(f"Added {added}", type="positive")
            email.set_value(None if USER_DIRECTORY else "")
            member_list.refresh()

        def confirm_remove(member):
            async def do_remove():
                try:
                    await run.io_bound(do_remove_vault_member, session, vault_id, member.email)
                except (LookupError, ValueError, PermissionError) as e:
                    ui.notify(str(e), type="negative")
                    return
                ui.notify(f"Removed {member.username}", type="positive")
                member_list.refresh()

            _open_confirm_dialog(
                "Remove access?",
                f'{member.username} will lose access to "{vault_name}" right away.',
                "Remove",
                do_remove,
            )

        # Add someone: email + role + Add, in one line
        _field_label("Add people")
        with ui.element("div").classes("gk-add-row"):
            email = _person_input(directory).classes("gk-add-email")
            role = ui.select({"view": "Can view", "edit": "Can edit"}, value="view") \
                .props("outlined dense").classes("gk-input gk-add-role").style("width: 140px")
            ui.button("Add", on_click=add).props("unelevated no-caps") \
                .classes("rounded-lg px-5 font-semibold gradient-bg").style("height: 40px")
        if not USER_DIRECTORY:
            email.on("keydown.enter", add)

        ui.label("People with access").classes("gk-field-key mt-7 mb-2")
        member_list()

        with ui.row().classes("w-full justify-end mt-7"):
            ui.button("Done", on_click=dialog.close) \
                .props("unelevated no-caps").classes("rounded-lg px-5 font-semibold gradient-bg")
    dialog.open()


def _open_manage_entry_sharing(session, entry):
    # Share ONE entry, see who it's shared with, and remove them (vault owner only)
    directory = load_user_directory(session) if USER_DIRECTORY else []
    has_access = {"emails": set()}      # filled by share_list, used to hide people already added
    with _dialog() as dialog, ui.card().classes("gk-dialog gk-dialog-lg gap-0"):
        _dialog_header("person_add_alt", "Share entry",
                       f'Give someone access to just "{entry.title}", not the rest of the vault.')

        @ui.refreshable
        def share_list():
            try:
                shares = load_entry_shares(session, entry.vault_entry_id)
            except PermissionError:
                ui.label("Only the vault owner can manage sharing.").classes("text-slate-500")
                return
            has_access["emails"] = {s.email for s in shares}
            if USER_DIRECTORY:
                email.set_options(_directory_options(directory, has_access["emails"]))
            if not shares:
                ui.label("Not shared with anyone yet.").classes("text-slate-500 text-sm")
                return
            with ui.column().classes("gk-member-list w-full gap-0"):
                for s in shares:
                    _member_row(s, lambda s=s: confirm_remove(s))

        async def add():
            try:
                await run.io_bound(do_share_entry, session, entry.vault_entry_id, email.value or "", role.value)
            except LookupError:
                ui.notify(f"No {APP_FULL_NAME} account uses that email.", type="negative")
                return
            except (ValueError, PermissionError) as e:
                ui.notify(str(e), type="negative")
                return
            added = (email.value or "").lower().strip()
            ui.notify(f"Shared with {added}", type="positive")
            email.set_value(None if USER_DIRECTORY else "")
            share_list.refresh()

        def confirm_remove(member):
            async def do_remove():
                try:
                    await run.io_bound(do_unshare_entry, session, entry.vault_entry_id, member.email)
                except (LookupError, PermissionError) as e:
                    ui.notify(str(e), type="negative")
                    return
                ui.notify(f"Removed {member.username}", type="positive")
                share_list.refresh()

            _open_confirm_dialog(
                "Remove access?",
                f'{member.username} will lose access to "{entry.title}" right away.',
                "Remove",
                do_remove,
            )

        # Add someone: email + role + Add, in one line
        _field_label("Add people")
        with ui.element("div").classes("gk-add-row"):
            email = _person_input(directory).classes("gk-add-email")
            role = ui.select({"view": "Can view", "edit": "Can edit"}, value="view") \
                .props("outlined dense").classes("gk-input gk-add-role").style("width: 140px")
            ui.button("Add", on_click=add).props("unelevated no-caps") \
                .classes("rounded-lg px-5 font-semibold gradient-bg").style("height: 40px")
        if not USER_DIRECTORY:
            email.on("keydown.enter", add)

        ui.label("Shared with").classes("gk-field-key mt-7 mb-2")
        share_list()

        with ui.row().classes("w-full justify-end mt-7"):
            ui.button("Done", on_click=dialog.close) \
                .props("unelevated no-caps").classes("rounded-lg px-5 font-semibold gradient-bg")
    dialog.open()


def _entry_fields(entry=None) -> dict:
    # The five entry inputs, shared by Add and Edit. Pre-filled when an entry is given.
    _field_label("Title")
    title = ui.input(placeholder="e.g. Amazon", value=entry.title if entry else "") \
        .props("outlined autofocus").classes("gk-input w-full")

    _field_label("Website")
    url = ui.input(placeholder="https://amazon.com", value=entry.url if entry else "") \
        .props("outlined").classes("gk-input w-full")
    with url.add_slot("prepend"):
        ui.icon("language").classes("text-slate-500")

    # Username and password side by side on wide screens, stacked on phones
    with ui.element("div").classes("grid grid-cols-1 sm:grid-cols-2 gap-x-4 w-full"):
        with ui.column().classes("gap-0 w-full"):
            _field_label("Username or email")
            username = ui.input(placeholder="aaron@example.com", value=entry.username if entry else "") \
                .props("outlined").classes("gk-input w-full")
        with ui.column().classes("gap-0 w-full"):
            _field_label("Password")
            password = ui.input(placeholder="••••••••••••", value=entry.password if entry else "",
                                password=True).props("outlined").classes("gk-input w-full")

            shown = {"value": False}

            def set_shown(value: bool):
                # Swap the input between dots and plain text, and flip the eye icon
                shown["value"] = value
                password.props("type=text" if value else "type=password")
                eye.props(f'icon={"visibility_off" if value else "visibility"}')

            def generate():
                # Fill in a strong password and show it, so the user can see what they got
                password.set_value(generate_password())
                set_shown(True)

            with password.add_slot("append"):
                eye = ui.button(icon="visibility", on_click=lambda: set_shown(not shown["value"])) \
                    .props("flat round dense color=grey-7").tooltip("Show or hide")
                ui.button(icon="autorenew", on_click=generate) \
                    .props("flat round dense color=grey-7").tooltip("Generate a strong password")

    _field_label("Notes")
    notes = ui.textarea(placeholder="Optional", value=entry.notes if entry else "") \
        .props("outlined autogrow").classes("gk-input w-full")

    return {"title": title, "url": url, "username": username, "password": password, "notes": notes}


# ========== Dialogs ==========

def _create_vault_dialog(session):
    # Popup with a name field. Built once per page, opened by the Create Vault buttons.
    with _dialog() as dialog, ui.card().classes("gk-dialog gap-0"):
        _dialog_header("create_new_folder", "Create vault", "Give your new vault a name.")

        _field_label("Vault name")
        name = ui.input(placeholder="e.g. Work").props("outlined autofocus").classes("gk-input w-full")

        async def submit():
            try:
                await run.io_bound(do_create_vault, session, name.value or "")
            except ValueError as e:
                ui.notify(str(e), type="negative")
                return
            app.storage.user["flash"] = f'Created "{name.value.strip()}"'
            ui.navigate.to("/vaults")

        name.on("keydown.enter", submit)
        _dialog_footer(dialog, "Create", submit)
    return dialog


def _create_entry_dialog(session, vault_id):
    # Popup for a new login. Built once per vault page, opened by the Add entry button.
    with _dialog() as dialog, ui.card().classes("gk-dialog gk-dialog-lg gap-0"):
        _dialog_header("key", "Add entry", "Save a new login to this vault.")
        f = _entry_fields()

        async def submit():
            try:
                await run.io_bound(do_create_entry, session, vault_id, f["title"].value, f["url"].value,
                                   f["username"].value, f["password"].value, f["notes"].value or "")
            except (ValueError, PermissionError) as e:
                ui.notify(str(e), type="negative")
                return
            app.storage.user["flash"] = f'Added "{f["title"].value.strip()}"'
            ui.navigate.to(f"/vault/{vault_id}")     # back to the vault you were in

        f["title"].on("keydown.enter", submit)
        _dialog_footer(dialog, "Add entry", submit)
    return dialog


def _open_edit_entry_dialog(session, entry, return_to: str | None = None):
    # Popup to change an entry (edit members, owners, and direct editors)
    with _dialog() as dialog, ui.card().classes("gk-dialog gk-dialog-lg gap-0"):
        _dialog_header("edit", "Edit entry", f'Update "{entry.title}".')
        f = _entry_fields(entry)

        async def submit():
            try:
                saved = await run.io_bound(do_update_entry, session, entry.vault_entry_id, f["title"].value,
                                           f["url"].value, f["username"].value, f["password"].value,
                                           f["notes"].value or "")
            except (ValueError, PermissionError) as e:
                ui.notify(str(e), type="negative")
                return
            if not saved:
                ui.notify("This entry no longer exists.", type="negative")
                return
            app.storage.user["flash"] = "Changes saved"
            ui.navigate.to(return_to or f"/vault/{entry.vault_id}/entry/{entry.vault_entry_id}")

        _dialog_footer(dialog, "Save changes", submit)
    dialog.open()


def _open_delete_entry_dialog(session, entry, return_to: str | None = None):
    # Move to Trash instead of deleting right away. It can be restored from the Trash page.
    with _dialog() as dialog, ui.card().classes("gk-dialog gap-0"):
        _dialog_header("delete_outline", "Move to Trash",
                       f'"{entry.title}" will be hidden for everyone who has access.', tone="red")
        ui.label("You can restore it from Trash until you empty it.").classes("text-sm text-slate-600 mt-5")

        async def submit():
            try:
                moved = await run.io_bound(do_trash_entry, session, entry.vault_entry_id)
            except PermissionError as e:
                ui.notify(str(e), type="negative")
                return
            if not moved:
                ui.notify("This entry no longer exists.", type="negative")
                return
            app.storage.user["flash"] = f'Moved "{entry.title}" to Trash'
            ui.navigate.to(return_to or f"/vault/{entry.vault_id}")

        _dialog_footer(dialog, "Move to Trash", submit, danger=True)
    dialog.open()


def _open_rename_dialog(session, v):
    # Popup to rename one vault (owners only)
    with _dialog() as dialog, ui.card().classes("gk-dialog gap-0"):
        _dialog_header("edit", "Rename vault", f'Choose a new name for "{v.name}".')

        _field_label("Vault name")
        name = ui.input(value=v.name).props("outlined autofocus").classes("gk-input w-full")

        async def submit():
            try:
                await run.io_bound(do_rename_vault, session, v.vault_id, name.value or "")
            except (ValueError, PermissionError) as e:
                ui.notify(str(e), type="negative")
                return
            app.storage.user["flash"] = f'Renamed to "{name.value.strip()}"'
            ui.navigate.to("/vaults")

        name.on("keydown.enter", submit)
        _dialog_footer(dialog, "Save", submit)
    dialog.open()


# ========== Cards and rows ==========

def _vault_card(session, v, count):
    # One vault tile: folder icon, name, item count, and a ⋮ menu
    with ui.element("div").classes("gk-vault-card p-4 cursor-pointer") \
            .on("click", lambda vid=v.vault_id: ui.navigate.to(f"/vault/{vid}")):
        with ui.row().classes("w-full items-center no-wrap gap-4"):
            with ui.element("div").classes("rounded-xl p-3 bg-green-50 flex"):
                ui.icon("o_lock").classes("text-2xl").style("color: #00994C")

            with ui.column().classes("gap-0 flex-1 min-w-0"):
                with ui.row().classes("items-center gap-2 no-wrap"):
                    ui.label(v.name).classes("font-semibold text-slate-900 truncate")
                    if not v.is_owner:
                        ui.label(f"from {v.owner_name}" if v.owner_name else "Shared") \
                            .classes("text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-600")
                ui.label(f"{count} item" if count == 1 else f"{count} items").classes("text-sm text-slate-500")

            # .stop keeps a click on ⋮ from also opening the vault
            with ui.button(icon="more_vert").props("flat round dense color=grey-8").on("click.stop", lambda: None):
                with ui.menu():
                    ui.menu_item("Open", on_click=lambda vid=v.vault_id: ui.navigate.to(f"/vault/{vid}"))
                    if v.is_owner:
                        ui.menu_item("Rename", on_click=lambda v=v: _open_rename_dialog(session, v))
                        ui.menu_item("Share", on_click=lambda v=v: _open_manage_vault_sharing(session, v.vault_id, v.name))


# Password health labels: (badge text, badge color class, icon, row highlight class)
# Red = reused, yellow = too weak / not strong enough
ISSUE_LABELS = {
    "reused": ("Reused Password", "gk-badge-red", "error_outline", "gk-row-red"),
    "weak": ("Weak Password", "gk-badge-amber", "warning_amber", "gk-row-amber"),
    "fair": ("Not Strong Enough", "gk-badge-amber", "warning_amber", "gk-row-amber"),
}


def _issue_badge(issue: str):
    # Small colored pill naming what's wrong with a password
    text, badge_class, badge_icon, _row_class = ISSUE_LABELS[issue]
    with ui.element("span").classes(f"gk-badge {badge_class}"):
        ui.icon(badge_icon).classes("text-base")
        ui.label(text)


def _entry_row(session, vault_id, e, can_share: bool, source: str | None = None, return_to: str | None = None,
               issue: str | None = None, issue_detail: str | None = None):
    # One entry in a vault: letter tile, title, username, quick-copy buttons.
    # With an issue ("reused", "weak", "fair"), the row is highlighted and says what's wrong.
    row_class = f" {ISSUE_LABELS[issue][3]}" if issue else ""
    with ui.element("div").classes("gk-vault-card p-4 cursor-pointer w-full" + row_class) \
            .on("click", lambda eid=e.vault_entry_id: ui.navigate.to(f"/vault/{vault_id}/entry/{eid}")):
        with ui.row().classes("w-full items-center no-wrap gap-4"):
            with ui.element("div").classes("rounded-xl bg-green-50 flex items-center justify-center") \
                    .style("width: 48px; height: 48px"):
                ui.label((e.title[:1] or "?").upper()).classes("text-lg font-extrabold").style("color: #00994C")

            with ui.column().classes("gap-0 flex-1 min-w-0"):
                ui.label(e.title).classes("font-semibold text-slate-900 truncate")
                ui.label(e.username or e.url or "No username").classes("text-sm text-slate-500 truncate")
                if source:
                    ui.label(source).classes("text-xs text-slate-400 truncate")
                # What's wrong with the password, and why
                if issue:
                    with ui.row().classes("items-center gap-2 mt-2"):
                        _issue_badge(issue)
                        if issue_detail:
                            ui.label(issue_detail).classes("text-xs text-slate-500")

            # Quick copy without opening the entry (.stop keeps the click off the row)
            with ui.row().classes("gap-1 no-wrap gk-hide-mobile"):
                if e.username:
                    ui.button(icon="person_outline", on_click=lambda u=e.username: copy_text(u, "Username")) \
                        .props("flat round dense color=grey-7").tooltip("Copy username") \
                        .on("click.stop", lambda: None)
                if e.password:
                    ui.button(icon="key", on_click=lambda p=e.password: copy_password(p)) \
                        .props("flat round dense color=grey-7").tooltip("Copy password") \
                        .on("click.stop", lambda: None)
                if can_share:
                    ui.button(icon="person_add_alt", on_click=lambda e=e: _open_manage_entry_sharing(session, e)) \
                        .props("flat round dense color=grey-7").tooltip("Share") \
                        .on("click.stop", lambda: None)
                # Edit: anyone who can edit this entry
                if e.can_edit:
                    ui.button(icon="edit", on_click=lambda e=e: _open_edit_entry_dialog(session, e, return_to=return_to)) \
                        .props("flat round dense color=grey-7").tooltip("Edit") \
                        .on("click.stop", lambda: None)
                # Move to Trash: vault owner only (same rule as Share)
                if can_share:
                    ui.button(icon="delete_outline", on_click=lambda e=e: _open_delete_entry_dialog(session, e, return_to=return_to)) \
                        .props("flat round dense color=grey-7").tooltip("Move to Trash") \
                        .on("click.stop", lambda: None)

            # Phones: the same actions in a ⋮ menu (the icons above are hidden there)
            with ui.button(icon="more_vert").props("flat round dense color=grey-7") \
                    .classes("gk-show-mobile").on("click.stop", lambda: None):
                with ui.menu():
                    if e.username:
                        ui.menu_item("Copy username", on_click=lambda u=e.username: copy_text(u, "Username"))
                    if e.password:
                        ui.menu_item("Copy password", on_click=lambda p=e.password: copy_password(p))
                    if can_share:
                        ui.menu_item("Share", on_click=lambda e=e: _open_manage_entry_sharing(session, e))
                    if e.can_edit:
                        ui.menu_item("Edit", on_click=lambda e=e: _open_edit_entry_dialog(session, e, return_to=return_to))
                    if can_share:
                        ui.menu_item("Move to Trash",
                                     on_click=lambda e=e: _open_delete_entry_dialog(session, e, return_to=return_to)) \
                            .classes("text-red-600")


def _detail_row(icon: str, key: str, value: str | None, link: str | None = None):
    # One labeled value on the credential page, with a copy button
    with ui.row().classes("gk-field-row w-full items-center no-wrap gap-4"):
        ui.icon(icon).classes("text-xl text-slate-400")
        with ui.column().classes("gap-0.5 flex-1 min-w-0"):
            ui.label(key).classes("gk-field-key")
            if link:
                ui.link(value, link, new_tab=True) \
                    .classes("text-green-700 font-medium no-underline hover:underline truncate")
            else:
                ui.label(value or "—").classes("text-slate-900 font-medium truncate")
        if value:
            if link:
                ui.button(icon="open_in_new", on_click=lambda: ui.navigate.to(link, new_tab=True)) \
                    .props("flat round dense color=grey-7").tooltip("Open website")
            ui.button(icon="content_copy", on_click=lambda: copy_text(value, key)) \
                .props("flat round dense color=grey-7").tooltip(f"Copy {key.lower()}")


def _password_row(password: str):
    # Hidden by default. The real password is only sent to the browser when revealed.
    mask = "•" * 12        # fixed length, so the dots don't give away how long it is
    shown = {"value": False}

    with ui.row().classes("gk-field-row w-full items-center no-wrap gap-4"):
        ui.icon("lock_outline").classes("text-xl text-slate-400")
        with ui.column().classes("gap-0.5 flex-1 min-w-0"):
            ui.label("Password").classes("gk-field-key")
            value_label = ui.label(mask).classes("gk-mono text-slate-900 font-medium truncate")

        def toggle():
            shown["value"] = not shown["value"]
            value_label.set_text(password if shown["value"] else mask)
            eye.props(f'icon={"visibility_off" if shown["value"] else "visibility"}')

        eye = ui.button(icon="visibility", on_click=toggle) \
            .props("flat round dense color=grey-7").tooltip("Show or hide")
        ui.button(icon="content_copy", on_click=lambda: copy_password(password)) \
            .props("flat round dense color=grey-7").tooltip("Copy password")


# Mermaid styling: soft green boxes, gray lines, the app's font
MERMAID_THEME = (
    "%%{init: {'theme': 'base', 'themeVariables': {"
    "'primaryColor': '#dcfce7', 'primaryBorderColor': '#16a34a', "
    "'primaryTextColor': '#0f172a', 'lineColor': '#94a3b8', "
    "'fontFamily': 'Inter, sans-serif', 'fontSize': '14px'}}}%%\n"
)


def _help_section(section_id: str, icon: str, title: str):
    # One help card with an id, so the chips at the top can scroll to it.
    # Returns the card's body column; use it with "with" to fill it.
    with ui.element("div").classes("gk-panel gk-help-section w-full p-6 mt-6").props(f"id={section_id}"):
        with ui.row().classes("items-center gap-3 no-wrap"):
            with ui.element("div").classes("rounded-xl p-2.5 bg-green-50 flex"):
                ui.icon(icon).classes("text-2xl").style("color: #00994C")
            ui.label(title).classes("text-xl font-bold text-slate-900")
        body = ui.column().classes("w-full gap-3 mt-4")
    return body


def _help_steps(steps: list[str]):
    # Numbered steps: (1) text, (2) text...
    for number, text in enumerate(steps, start=1):
        with ui.row().classes("items-start gap-3 no-wrap"):
            ui.label(str(number)).classes("gk-help-step")
            ui.label(text).classes("text-slate-700 pt-0.5")


def _help_points(points: list[str]):
    # Short bullet points with a green check
    for text in points:
        with ui.row().classes("items-start gap-3 no-wrap"):
            ui.icon("check_circle").classes("text-lg mt-0.5").style("color: #00994C")
            ui.label(text).classes("text-slate-700")


def _help_diagram(definition: str):
    # A small Mermaid diagram on a light card
    with ui.element("div").classes("gk-diagram w-full"):
        ui.mermaid(MERMAID_THEME + definition)


def _scroll_to(section_id: str):
    # Smoothly scroll the page to a help section
    ui.run_javascript(
        f"document.getElementById('{section_id}').scrollIntoView({{behavior: 'smooth', block: 'start'}})"
    )


# ========== Pages ==========

@ui.page("/")
def dashboard_page():
    # Protected page: no valid session → back to login
    session = current_session()
    if session is None:
        return RedirectResponse("/login")

    _apply_theme()
    _apply_user_theme()
    show_flash()

    vault_infos, entries, trash_count = load_dashboard_data(session)
    report = health.analyze(entries)
    vaults = [(v, 0) for v in vault_infos]      # the sidebar only needs names
    vault_dialog = _create_vault_dialog(session)
    main_area = _app_shell(vaults, vault_dialog.open, active="dashboard", show_search=False)

    # Letter tiles cycle through soft colors, picked from the title so each site keeps its color
    tile_tones = ["green", "blue", "violet", "amber", "rose", "teal"]

    def stat_card(icon, title, subtitle, target, tone):
        with ui.element("div").classes(f"gk-stat gk-tone-{tone}").on("click", lambda: ui.navigate.to(target)):
            with ui.row().classes("w-full items-center no-wrap gap-4"):
                with ui.element("div").classes("gk-stat-icon"):
                    ui.icon(icon).classes("text-2xl")
                with ui.column().classes("gap-0 flex-1 min-w-0"):
                    ui.label(title).classes("text-lg font-bold text-slate-900")
                    ui.label(subtitle).classes("text-sm text-slate-500")
                ui.icon("chevron_right").classes("text-xl text-slate-400")

    with main_area:
        # ===== Header with a soft green wave =====
        with ui.element("div").classes("gk-dash-hero mt-2"):
            ui.html("""<svg class="wave" viewBox="0 0 400 200" aria-hidden="true">
                <defs><linearGradient id="dw" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0" stop-color="#00994C" stop-opacity="0"/>
                <stop offset="1" stop-color="#00B570" stop-opacity="0.9"/></linearGradient></defs>
                <path d="M0 170 C 120 170, 160 90, 260 90 S 360 40, 400 20" fill="none" stroke="url(#dw)" stroke-width="3"/>
                </svg>""", sanitize=False)
            ui.label("Dashboard").classes("text-4xl font-extrabold tracking-tight text-slate-900")
            ui.label("Your security overview at a glance.").classes("text-slate-500 mt-1")

        # ===== Cards: 2 columns on phones and up =====
        with ui.element("div").classes("grid grid-cols-1 sm:grid-cols-2 gap-4 w-full mt-4"):
            count_v = len(vault_infos)
            count_p = report["total"]
            stat_card("o_lock", "Vaults", f"{count_v} vault" if count_v == 1 else f"{count_v} vaults", "/vaults", "blue")
            stat_card("key", "Passwords", f"{count_p} password" if count_p == 1 else f"{count_p} passwords", "/passwords", "violet")

            # Password Safety: red share of the bar = insecure
            with ui.element("div").classes("gk-stat gk-tone-green").on("click", lambda: ui.navigate.to("/passwords?filter=issues")):
                with ui.row().classes("w-full items-center no-wrap gap-4"):
                    with ui.element("div").classes("gk-stat-icon"):
                        ui.icon("o_shield").classes("text-2xl")
                    ui.label("Password Safety").classes("text-lg font-bold text-slate-900 flex-1")
                    ui.icon("chevron_right").classes("text-xl text-slate-400")
                share = (report["insecure"] / report["total"] * 100) if report["total"] else 0
                with ui.element("div").classes("gk-safety-bar w-full mt-4"):
                    ui.element("div").style(f"width: {share:.0f}%")
                with ui.row().classes("w-full justify-between mt-2"):
                    ui.label(f'{report["insecure"]} insecure').classes("text-sm font-semibold").style("color: #ef4444")
                    ui.label(f'{report["strong"]} strong').classes("text-sm font-semibold").style("color: #16a34a")

            # Trash: count, or "Clean" when empty
            with ui.element("div").classes("gk-stat gk-tone-amber").on("click", lambda: ui.navigate.to("/trash")):
                with ui.row().classes("w-full items-center no-wrap gap-4"):
                    with ui.element("div").classes("gk-stat-icon"):
                        ui.icon("delete_outline").classes("text-2xl")
                    ui.label("Trash").classes("text-lg font-bold text-slate-900 flex-1")
                    ui.icon("chevron_right").classes("text-xl text-slate-400")
                with ui.row().classes("items-center gap-2 mt-4"):
                    if trash_count == 0:
                        ui.icon("check_circle").classes("text-xl").style("color: #16a34a")
                        ui.label("Clean").classes("text-slate-600 font-medium")
                    else:
                        ui.label(f"{trash_count} item" if trash_count == 1 else f"{trash_count} items") \
                            .classes("text-slate-600 font-medium")

        # ===== Password Issues =====
        with ui.element("div").classes("gk-panel w-full p-5 mt-4"):
            with ui.row().classes("w-full items-center justify-between no-wrap mb-2"):
                ui.label("Password Issues").classes("text-xl font-bold text-slate-900")
                if report["issues"]:
                    ui.link("View All", "/passwords?filter=issues").classes("font-semibold no-underline").style("color: #16a34a")

            if not report["issues"]:
                with ui.row().classes("items-center gap-2 py-3"):
                    ui.icon("verified").classes("text-xl").style("color: #16a34a")
                    ui.label("No issues found. Every password is strong and unique.").classes("text-slate-600")
            else:
                for item in report["issues"][:5]:
                    e = item.entry
                    with ui.row().classes("gk-issue-row w-full items-center no-wrap gap-3") \
                            .on("click", lambda e=e: ui.navigate.to(f"/vault/{e.vault_id}/entry/{e.vault_entry_id}")):
                        tone = tile_tones[sum(map(ord, e.title.lower())) % len(tile_tones)]
                        with ui.element("div").classes(f"gk-tile gk-tone-{tone} rounded-xl flex items-center justify-center shrink-0") \
                                .style("width: 44px; height: 44px"):
                            ui.label((e.title[:1] or "?").upper()).classes("text-lg font-extrabold")
                        with ui.column().classes("gap-0 flex-1 min-w-0"):
                            ui.label(e.title).classes("font-semibold text-slate-900 truncate")
                            ui.label(e.username or e.url or "").classes("text-sm text-slate-500 truncate")
                        _issue_badge(item.issue)
                        ui.icon("chevron_right").classes("gk-issue-chevron text-xl text-slate-400")

        _mobile_credit()


@ui.page("/vaults")
def vaults_page():
    # Protected page: no valid session → back to login
    session = current_session()
    if session is None:
        return RedirectResponse("/login")

    _apply_theme()
    _apply_user_theme()
    show_flash()

    vaults = load_vaults(session)
    create_dialog = _create_vault_dialog(session)
    state = {"search": ""}

    @ui.refreshable
    def vault_grid():
        # Redraws only the cards when the search text changes
        term = state["search"].lower()
        shown = [(v, count) for v, count in vaults if term in v.name.lower()]
        if not shown:
            ui.label("No vaults match your search.").classes("text-slate-500 mt-8")
            return
        with ui.element("div").classes("grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 w-full mt-6"):
            for v, count in shown:
                _vault_card(session, v, count)

    def on_search(text):
        state["search"] = text
        vault_grid.refresh()

    main_area = _app_shell(vaults, create_dialog.open, on_search)

    with main_area:
        # Title on the left, Create Vault on the right
        with ui.row().classes("w-full items-end justify-between no-wrap mt-8"):
            with ui.column().classes("gap-1"):
                ui.label("Vaults").classes("text-3xl font-extrabold tracking-tight text-slate-900")
                ui.label("Organize your items into vaults.").classes("text-slate-500")
            ui.button("Create Vault", icon="add", on_click=create_dialog.open) \
                .props("unelevated no-caps").classes("rounded-xl px-5 font-semibold gradient-bg")

        vault_grid()

        _mobile_credit()


@ui.page("/login")
def login_page(request: Request):
    ip_address = request.client.host
    _apply_theme()
    show_flash()      # shows "Successfully created new account!" after registering

    # Full-window background, no NiceGUI padding around the page
    # Background comes from CSS, so it can switch with the theme
    ui.query("body").classes("gk-auth-page")
    _apply_user_theme()
    ui.query(".nicegui-content").classes("p-0")

    async def try_login():
        try:
            session = await run.io_bound(do_login, email.value, password.value, ip_address)
        except auth.InvalidCredentialsError:
            ui.notify("Incorrect email or password", type="negative")
        except auth.AccountLockedError:
            ui.notify("Too many attempts. Try again later.", type="negative")
        else:
            # A brand-new token every login, so an old token can never be reused
            app.storage.user["token"] = sessions.create(session)
            app.storage.user["flash"] = "Welcome back!"
            ui.navigate.to("/")

    with ui.element("div").classes("gk-login-stage"):

        # ===== Form (right side, vertically centered) =====
        with ui.column().classes("gk-login-form gap-0"):

            # Title: "Welcome to Grisha" dark, "Key" in the gradient
            ui.label("Welcome to").classes("text-4xl md:text-5xl font-extrabold tracking-tight text-slate-900")
            _brand("text-4xl md:text-5xl")
            ui.label("Sign in to access your vault.").classes("text-lg text-slate-500 mt-3")

            email = ui.input(placeholder="Email address").props("outlined") \
                .classes("gk-login-input w-full mt-8")
            with email.add_slot("prepend"):
                ui.icon("mail_outline").classes("text-slate-600")

            password = ui.input(placeholder="Password", password=True, password_toggle_button=True) \
                .props("outlined").classes("gk-login-input w-full mt-5").on("keydown.enter", try_login)
            with password.add_slot("prepend"):
                ui.icon("lock_outline").classes("text-slate-600")

            ui.button("Sign in", icon="key", on_click=try_login) \
                .props("unelevated no-caps size=lg") \
                .classes("w-full mt-6 rounded-xl font-semibold gradient-bg").style("height: 58px")

            # "Forgot your password?  ·  Create account"
            with ui.row().classes("w-full justify-center items-center gap-3 mt-8 no-wrap"):
                ui.label("Forgot your password?") \
                    .classes("text-slate-600 cursor-pointer hover:text-slate-900") \
                    .on("click", lambda: ui.navigate.to("/recover"))
                ui.label("·").classes("text-slate-400")
                ui.link("Create account", "/register") \
                    .classes("text-green-600 font-semibold no-underline")

        _credit_links("gk-credit-bottom")


@ui.page("/recover")
def recover_page(request: Request):
    ip_address = request.client.host
    _apply_theme()

    # Same full-window look as the login page
    # Background comes from CSS, so it can switch with the theme
    ui.query("body").classes("gk-auth-page")
    _apply_user_theme()
    ui.query(".nicegui-content").classes("p-0")

    async def try_recover():
        if (new_pw.value or "") != (confirm_pw.value or ""):
            ui.notify("New passwords do not match.", type="negative")
            return
        try:
            new_code = await run.io_bound(do_recover_account, email.value or "", code.value or "",
                                          new_pw.value or "", ip_address)
        except auth.InvalidCredentialsError:
            ui.notify("Incorrect email or recovery code.", type="negative")
            return
        except auth.AccountLockedError:
            ui.notify("Too many attempts. Try again later.", type="negative")
            return
        except auth.PasswordComplexityError:
            ui.notify("Password must be at least 12 and no more than 256 characters long.", type="negative")
            return

        def done():
            app.storage.user["flash"] = "Password reset. Sign in with your new password."
            ui.navigate.to("/login")

        # The used code is gone; show the new one once
        _open_recovery_code_dialog(new_code, (email.value or "").strip().lower(), done)

    with ui.element("div").classes("gk-login-stage"):
        with ui.column().classes("gk-login-form gap-0"):
            ui.label("Reset your").classes("text-4xl md:text-5xl font-extrabold tracking-tight text-slate-900")
            ui.label("master password").classes("text-4xl md:text-5xl font-extrabold tracking-tight gradient-text")
            ui.label("Use the recovery code you saved when you signed up.").classes("text-lg text-slate-500 mt-3")

            email = ui.input(placeholder="Email address").props("outlined").classes("gk-login-input w-full mt-8")
            with email.add_slot("prepend"):
                ui.icon("mail_outline").classes("text-slate-600")

            code = ui.input(placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX").props("outlined") \
                .classes("gk-login-input gk-mono w-full mt-5")
            with code.add_slot("prepend"):
                ui.icon("key").classes("text-slate-600")

            new_pw = ui.input(placeholder="New master password", password=True, password_toggle_button=True) \
                .props("outlined").classes("gk-login-input w-full mt-5")
            with new_pw.add_slot("prepend"):
                ui.icon("lock_outline").classes("text-slate-600")

            confirm_pw = ui.input(placeholder="Confirm new password", password=True, password_toggle_button=True) \
                .props("outlined").classes("gk-login-input w-full mt-5").on("keydown.enter", try_recover)
            with confirm_pw.add_slot("prepend"):
                ui.icon("lock_outline").classes("text-slate-600")

            ui.button("Reset password", icon="lock_reset", on_click=try_recover) \
                .props("unelevated no-caps size=lg") \
                .classes("w-full mt-6 rounded-xl font-semibold gradient-bg").style("height: 58px")

            with ui.row().classes("w-full justify-center mt-8"):
                ui.link("Back to sign in", "/login").classes("text-green-600 font-semibold no-underline")


@ui.page("/register")
def register(request: Request):
    ip_address = request.client.host
    _apply_theme()
    # Same full-window look as the login page
    # Background comes from CSS, so it can switch with the theme
    ui.query("body").classes("gk-auth-page")
    _apply_user_theme()
    ui.query(".nicegui-content").classes("p-0")

    async def try_register():
        # Check the confirm fields here, before any slow work
        if email.value.strip().lower() != confirm_email.value.strip().lower():
            ui.notify("Emails do not match.", type="negative")
            return
        if password.value != confirm_password.value:
            ui.notify("Passwords do not match.", type="negative")
            return

        try:
            user_id = await run.io_bound(do_register, username.value, email.value, password.value, ip_address)
        except auth.UserExistsError:
            ui.notify("Username or email already exists.", type="negative")
            return
        except auth.AccountLockedError:
            ui.notify("Too many attempts. Try again later.", type="negative")
            return
        except auth.PasswordComplexityError:
            ui.notify("Password must be at least 12 and no more than 256 characters long.", type="negative")
            return

        # Account created: make the first recovery code and show it once
        # (the user_id comes back from do_register; capture it from the existing call)
        try:
            code = await run.io_bound(do_create_recovery_code, user_id, password.value)
        except Exception:
            # Account exists either way; they can create a code later in Settings
            app.storage.user["flash"] = "Account created. Create a recovery code in Settings."
            ui.navigate.to("/login")
            return

        def done():
            app.storage.user["flash"] = "Successfully created new account!"
            ui.navigate.to("/login")

        _open_recovery_code_dialog(code, email.value.strip().lower(), done)

    with ui.element("div").classes("gk-auth-flow"):
        with ui.column().classes("gk-auth-form gap-0"):

            # Title: "Create your" on one line, the app name + "account" on the next
            ui.label("Create your").classes("text-4xl md:text-5xl font-extrabold tracking-tight text-slate-900")
            with ui.row().classes("gap-3 no-wrap items-baseline"):
                _brand("text-4xl md:text-5xl")
                ui.label("account").classes("text-4xl md:text-5xl font-extrabold tracking-tight text-slate-900")
            ui.label("Set up your vault in a minute.").classes("text-lg text-slate-500 mt-3")

            username = ui.input(placeholder="Username").props("outlined") \
                .classes("gk-login-input w-full mt-8")
            with username.add_slot("prepend"):
                ui.icon("person_outline").classes("text-slate-600")

            email = ui.input(placeholder="Email address").props("outlined") \
                .classes("gk-login-input w-full mt-5")
            with email.add_slot("prepend"):
                ui.icon("mail_outline").classes("text-slate-600")

            confirm_email = ui.input(placeholder="Confirm email address").props("outlined") \
                .classes("gk-login-input w-full mt-5")
            with confirm_email.add_slot("prepend"):
                ui.icon("mail_outline").classes("text-slate-600")

            password = ui.input(placeholder="Master password", password=True, password_toggle_button=True) \
                .props("outlined").classes("gk-login-input w-full mt-5")
            with password.add_slot("prepend"):
                ui.icon("lock_outline").classes("text-slate-600")

            confirm_password = ui.input(placeholder="Confirm master password", password=True,
                                        password_toggle_button=True) \
                .props("outlined").classes("gk-login-input w-full mt-5").on("keydown.enter", try_register)
            with confirm_password.add_slot("prepend"):
                ui.icon("lock_outline").classes("text-slate-600")

            ui.label("You'll get a recovery code next. It's the only way to reset your master password if you forget it.") \
                .classes("text-sm text-slate-500 mt-3")

            ui.button("Create account", icon="person_add_alt", on_click=try_register) \
                .props("unelevated no-caps size=lg") \
                .classes("w-full mt-6 rounded-xl font-semibold gradient-bg").style("height: 58px")

            # "Already have an account?  ·  Sign in"
            with ui.row().classes("w-full justify-center items-center gap-3 mt-8 no-wrap"):
                ui.label("Already have an account?").classes("text-slate-600")
                ui.label("·").classes("text-slate-400")
                ui.link("Sign in", "/login").classes("text-green-600 font-semibold no-underline")

        _credit_links("gk-credit-bottom")


@ui.page("/vault/{vault_id}")
def vault_detail_page(vault_id: str):
    # Protected page: no valid session → back to login
    session = current_session()
    if session is None:
        return RedirectResponse("/login")

    _apply_theme()
    _apply_user_theme()
    show_flash()

    # Only vaults this user is a member of
    vaults = load_vaults(session)
    current = next((v for v, _count in vaults if v.vault_id == vault_id), None)
    if current is None:
        app.storage.user["flash"] = "That vault doesn't exist or you don't have access."
        return RedirectResponse("/")

    # This vault's entries only
    vault_entries = [e for e in load_entries(session) if e.vault_id == vault_id]
    state = {"search": ""}

    @ui.refreshable
    def entry_list():
        # Redraws only the rows when the search text changes
        term = state["search"].lower()
        shown = [e for e in vault_entries
                 if term in e.title.lower() or term in (e.username or "").lower() or term in (e.url or "").lower()]
        if not vault_entries:
            ui.label("No entries yet.").classes("text-slate-500 mt-8")
            return
        if not shown:
            ui.label("No entries match your search.").classes("text-slate-500 mt-8")
            return
        with ui.column().classes("w-full gap-3 mt-6"):
            for e in shown:
                _entry_row(session, vault_id, e, current.is_owner, return_to=f"/vault/{vault_id}")

    def on_search(text):
        state["search"] = text
        entry_list.refresh()

    # Two different popups: one for the sidebar's Create Vault, one for Add entry
    vault_dialog = _create_vault_dialog(session)
    entry_dialog = _create_entry_dialog(session, vault_id)
    main_area = _app_shell(vaults, vault_dialog.open, on_search, search_placeholder="Search this vault...",
                           active_vault_id=vault_id)

    with main_area:
        # Vault name on the left, Add entry on the right (only if allowed)
        with ui.row().classes("w-full items-end justify-between no-wrap mt-8"):
            with ui.column().classes("gap-1"):
                with ui.row().classes("items-center gap-3 no-wrap"):
                    ui.label(current.name).classes("text-3xl font-extrabold tracking-tight text-slate-900")
                    if not current.is_owner:
                        ui.label("Shared with you").classes("gk-pill")
                count = len(vault_entries)
                ui.label(f"{count} item" if count == 1 else f"{count} items").classes("text-slate-500")
            # Right side: Share (owner only) and Add entry (if allowed), side by side
            with ui.row().classes("items-center gap-2 no-wrap"):
                if current.is_owner:
                    ui.button("Share", icon="group_add",
                              on_click=lambda: _open_manage_vault_sharing(session, vault_id, current.name)) \
                        .props("outline no-caps color=grey-8").classes("rounded-xl px-5 font-semibold gk-hide-mobile")
                if current.can_edit:
                    ui.button("Add entry", icon="add", on_click=entry_dialog.open) \
                        .props("unelevated no-caps").classes("rounded-xl px-5 font-semibold gradient-bg gk-hide-mobile")
                if current.can_edit:
                    ui.button(icon="add", on_click=entry_dialog.open) \
                        .props("unelevated round").classes("gradient-bg gk-show-mobile").tooltip("Add entry")
                if current.is_owner:
                    with ui.button(icon="more_vert").props("flat round color=grey-8").classes("gk-show-mobile"):
                        with ui.menu():
                            ui.menu_item("Share vault",
                                         on_click=lambda: _open_manage_vault_sharing(session, vault_id, current.name))

        entry_list()

        _mobile_credit()


@ui.page("/vault/{vault_id}/entry/{entry_id}")
def entry_detail_page(vault_id: str, entry_id: str):
    # Protected page: no valid session → back to login
    session = current_session()
    if session is None:
        return RedirectResponse("/login")

    _apply_theme()
    _apply_user_theme()
    show_flash()

    # get_entry checks BOTH paths (vault member or direct share) and decrypts
    entry = load_entry(session, entry_id)
    if entry is None or entry.vault_id != vault_id:
        app.storage.user["flash"] = "That entry doesn't exist or you don't have access."
        return RedirectResponse("/")

    vaults = load_vaults(session)
    current = next((v for v, _count in vaults if v.vault_id == vault_id), None)   # None = direct share only
    is_owner = current is not None and current.is_owner
    link = safe_url(entry.url)

    vault_dialog = _create_vault_dialog(session)
    main_area = _app_shell(vaults, vault_dialog.open, active_vault_id=vault_id)

    with main_area:

        # ===== Breadcrumb: Vaults › Work › Gmail =====
        with ui.row().classes("items-center gap-1 mt-8 text-sm no-wrap"):
            ui.link("Vaults", "/vaults").classes("text-slate-500 no-underline hover:text-slate-900")
            ui.icon("chevron_right").classes("text-slate-400")
            if current:
                ui.link(current.name, f"/vault/{vault_id}").classes("text-slate-500 no-underline hover:text-slate-900")
            else:
                ui.label("Shared with you").classes("text-slate-500")
            ui.icon("chevron_right").classes("text-slate-400")
            ui.label(entry.title).classes("text-slate-900 font-medium truncate")

        # ===== Title area: letter tile, name, website, actions =====
        with ui.row().classes("w-full items-center justify-between no-wrap gap-4 mt-6"):
            with ui.row().classes("items-center gap-5 no-wrap min-w-0"):
                ui.label((entry.title[:1] or "?").upper()).classes("gk-letter-tile shrink-0")
                with ui.column().classes("gap-1 min-w-0"):
                    ui.label(entry.title).classes("text-3xl font-extrabold tracking-tight text-slate-900 truncate")
                    with ui.row().classes("items-center gap-2 no-wrap"):
                        if entry.can_edit:
                            ui.label("Can edit").classes("gk-pill gk-pill-green")
                        else:
                            ui.label("View only").classes("gk-pill")
                        if current is None:
                            ui.label("Shared with you").classes("gk-pill")

            with ui.row().classes("items-center gap-2 no-wrap gk-hide-mobile"):
                if is_owner:
                    ui.button("Share", icon="person_add_alt",
                              on_click=lambda: _open_manage_entry_sharing(session, entry)) \
                        .props("outline no-caps color=grey-8").classes("rounded-xl px-5 font-semibold")
                if entry.can_edit:
                    ui.button("Edit", icon="edit", on_click=lambda: _open_edit_entry_dialog(session, entry)) \
                        .props("unelevated no-caps").classes("rounded-xl px-5 font-semibold gradient-bg")
                if is_owner:
                    with ui.button(icon="more_vert").props("flat round color=grey-8"):
                        with ui.menu():
                            ui.menu_item("Move to Trash", on_click=lambda: _open_delete_entry_dialog(session, entry)) \
                                .classes("text-red-600")

            # Phones: Share, Edit, and Move to Trash in one ⋮ menu
            if is_owner or entry.can_edit:
                with ui.button(icon="more_vert").props("flat round color=grey-8").classes("gk-show-mobile"):
                    with ui.menu():
                        if is_owner:
                            ui.menu_item("Share", on_click=lambda: _open_manage_entry_sharing(session, entry))
                        if entry.can_edit:
                            ui.menu_item("Edit", on_click=lambda: _open_edit_entry_dialog(session, entry))
                        if is_owner:
                            ui.menu_item("Move to Trash", on_click=lambda: _open_delete_entry_dialog(session, entry)) \
                                .classes("text-red-600")

        # ===== Login details =====
        ui.label("Login details").classes("gk-field-key mt-10 mb-3")
        with ui.element("div").classes("gk-panel w-full"):
            _detail_row("person_outline", "Username", entry.username)
            _password_row(entry.password)
            _detail_row("language", "Website", entry.url, link=link)

        # ===== Notes (only if there are any) =====
        if entry.notes:
            ui.label("Notes").classes("gk-field-key mt-8 mb-3")
            with ui.element("div").classes("gk-panel w-full p-5"):
                ui.label(entry.notes).classes("text-slate-700 whitespace-pre-wrap")

        _mobile_credit()


@ui.page("/passwords")
def passwords_page(filter: str = "all"):
    # Protected page: no valid session → back to login
    session = current_session()
    if session is None:
        return RedirectResponse("/login")

    _apply_theme()
    _apply_user_theme()
    show_flash()

    # Load ONCE. Search, filter, and sort below all work on this in memory.
    vaults, entries, direct_owners = load_passwords_data(session)
    vault_by_id = {v.vault_id: v for v, _count in vaults}
    owned_ids = {v.vault_id for v, _count in vaults if v.is_owner}
    state = {"search": "", "filter": filter if filter in ("all", "shared", "issues") else "all", "sort": "asc"}

    # Password health, worked out once in memory: what's wrong with each entry, and why
    issue_by_id = {i.entry.vault_entry_id: i.issue for i in health.analyze(entries)["issues"]}
    titles_by_password: dict[str, list[str]] = {}
    for e in entries:
        if e.password:
            titles_by_password.setdefault(e.password, []).append(e.title)

    def issue_detail(e) -> str:
        # One short sentence telling the user what to fix
        issue = issue_by_id.get(e.vault_entry_id)
        if issue == "reused":
            others = list(titles_by_password[e.password])
            others.remove(e.title)
            names = ", ".join(others[:3]) + (f" and {len(others) - 3} more" if len(others) > 3 else "")
            return f"Same password as {names}. Use a different one for each site."
        if issue == "weak":
            return "Too short or too common. It would be easy to guess."
        if issue == "fair":
            return "Could be guessed with time. Make it longer or add symbols."
        return ""

    def source_label(e) -> str:
        # Where this entry comes from, so nobody wonders why it's in the list
        v = vault_by_id.get(e.vault_id)
        if v is None:
            return f"Shared directly · from {direct_owners.get(e.vault_entry_id, 'someone')}"
        if v.is_owner:
            return v.name
        return f"{v.name} · from {v.owner_name}" if v.owner_name else v.name

    @ui.refreshable
    def password_list():
        shown = entries

        # [All | Shared with me]: shared = anything NOT in a vault you own
        if state["filter"] == "shared":
            shown = [e for e in shown if e.vault_id not in owned_ids]

        # Needs attention: weak, reused, or not strong enough
        if state["filter"] == "issues":
            shown = [e for e in shown if e.vault_entry_id in issue_by_id]

        # Search title, username, and website
        term = state["search"].lower()
        if term:
            shown = [e for e in shown
                     if term in e.title.lower()
                     or term in (e.username or "").lower()
                     or term in (e.url or "").lower()]

        # A → Z or Z → A, ignoring capital letters
        shown = sorted(shown, key=lambda e: e.title.lower(), reverse=state["sort"] == "desc")

        count = len(shown)
        ui.label(f"{count} item" if count == 1 else f"{count} items").classes("text-slate-500 mt-4")

        if not entries:
            ui.label("No passwords yet.").classes("text-slate-500 mt-6")
            return
        if not shown:
            ui.label("Nothing matches.").classes("text-slate-500 mt-6")
            return

        with ui.column().classes("w-full gap-3 mt-4"):
            for e in shown:
                _entry_row(session, e.vault_id, e, e.vault_id in owned_ids, source=source_label(e),
                           return_to=f"/passwords?filter={state['filter']}",
                           issue=issue_by_id.get(e.vault_entry_id), issue_detail=issue_detail(e))

    def on_search(text):
        state["search"] = text
        password_list.refresh()

    def on_filter(e):
        state["filter"] = e.value
        password_list.refresh()

    def on_sort(e):
        state["sort"] = e.value
        password_list.refresh()

    vault_dialog = _create_vault_dialog(session)
    main_area = _app_shell(vaults, vault_dialog.open, on_search,
                           search_placeholder="Search passwords...", active="passwords")

    with main_area:
        with ui.column().classes("gap-1 mt-8"):
            ui.label("Passwords").classes("text-3xl font-extrabold tracking-tight text-slate-900")
            ui.label("Every login you can open, in one place.").classes("text-slate-500")

        # Filter on the left, sort on the right
        with ui.row().classes("w-full items-center justify-between no-wrap mt-6 gap-4"):
            ui.toggle({"all": "All", "shared": "Shared with me", "issues": "Needs attention"},
                      value=state["filter"], on_change=on_filter) \
                .props('no-caps unelevated color=transparent text-color=grey-8 toggle-color=primary toggle-text-color=white') \
                .classes("gk-segmented")
            ui.select({"asc": "A → Z", "desc": "Z → A"}, value="asc", label="Sort", on_change=on_sort) \
                .props("outlined dense").classes("gk-input").style("width: 140px")

        password_list()

        _mobile_credit()


@ui.page("/trash")
def trash_page():
    # Protected page: no valid session → back to login
    session = current_session()
    if session is None:
        return RedirectResponse("/login")

    _apply_theme()
    _apply_user_theme()
    show_flash()

    vaults = load_vaults(session)
    vault_names = {v.vault_id: v.name for v, _count in vaults}

    @ui.refreshable
    def trash_list():
        # Reload each time, since restore and delete change what's here
        items = load_trash(session)

        with ui.row().classes("w-full items-end justify-between no-wrap mt-8"):
            with ui.column().classes("gap-1"):
                ui.label("Trash").classes("text-3xl font-extrabold tracking-tight text-slate-900")
                count = len(items)
                ui.label(f"{count} item" if count == 1 else f"{count} items").classes("text-slate-500")
            if items:
                ui.button("Empty trash", icon="delete_forever", on_click=confirm_empty) \
                    .props("outline no-caps color=negative").classes("rounded-xl px-5 font-semibold")

        ui.label("Only entries from vaults you own show up here. Others with access can't see them until restored.") \
            .classes("text-sm text-slate-500 mt-3")

        if not items:
            ui.label("Trash is empty.").classes("text-slate-500 mt-8")
            return

        with ui.column().classes("w-full gap-3 mt-6"):
            for item in items:
                e = item.entry
                with ui.element("div").classes("gk-vault-card p-4 w-full"):
                    with ui.row().classes("w-full items-center no-wrap gap-4"):
                        with ui.element("div").classes("rounded-xl bg-slate-100 flex items-center justify-center shrink-0") \
                                .style("width: 48px; height: 48px"):
                            ui.label((e.title[:1] or "?").upper()).classes("text-lg font-extrabold text-slate-500")
                        with ui.column().classes("gap-0 flex-1 min-w-0"):
                            ui.label(e.title).classes("font-semibold text-slate-900 truncate w-full")
                            # deleted_at looks like "2026-11-16 14:03:22" (UTC); show the date part
                            ui.label(vault_names.get(e.vault_id, "Vault")) \
                                .classes("text-sm text-slate-500 truncate w-full")
                            ui.label(f"Moved to Trash {item.deleted_at[:10]}") \
                                .classes("text-xs text-slate-400 truncate w-full")
                        with ui.row().classes("gap-1 no-wrap items-center gk-hide-mobile shrink-0"):
                            ui.button("Restore", icon="restore", on_click=lambda e=e: restore(e)) \
                                .props("outline no-caps color=grey-8").classes("rounded-lg")
                            ui.button(icon="delete_forever", on_click=lambda e=e: confirm_delete(e)) \
                                .props("flat round color=negative").tooltip("Delete forever")
                        with ui.button(icon="more_vert").props("flat round dense color=grey-7").classes("gk-show-mobile shrink-0"):
                            with ui.menu():
                                ui.menu_item("Restore", on_click=lambda e=e: restore(e))
                                ui.menu_item("Delete forever", on_click=lambda e=e: confirm_delete(e)) \
                                    .classes("text-red-600")

    async def restore(e):
        restored = await run.io_bound(do_restore_entry, session, e.vault_entry_id)
        if not restored:
            ui.notify("This entry is no longer in the Trash.", type="negative")
        else:
            ui.notify(f'Restored "{e.title}"', type="positive")
        trash_list.refresh()

    def confirm_delete(e):
        async def do_delete():
            deleted = await run.io_bound(do_delete_forever, session, e.vault_entry_id)
            if not deleted:
                ui.notify("This entry is no longer in the Trash.", type="negative")
            else:
                ui.notify(f'Deleted "{e.title}" forever', type="positive")
            trash_list.refresh()

        _open_confirm_dialog(
            "Delete forever?",
            f'"{e.title}" will be permanently deleted. This can\'t be undone.',
            "Delete forever",
            do_delete,
        )

    def confirm_empty():
        async def do_empty():
            removed = await run.io_bound(do_empty_trash, session)
            ui.notify(f"Deleted {removed} item{'s' if removed != 1 else ''} forever", type="positive")
            trash_list.refresh()

        _open_confirm_dialog(
            "Empty trash?",
            "Everything in the Trash will be permanently deleted. This can't be undone.",
            "Empty trash",
            do_empty,
        )

    vault_dialog = _create_vault_dialog(session)
    main_area = _app_shell(vaults, vault_dialog.open, active="trash", show_search=False)

    with main_area:
        trash_list()

        _mobile_credit()


@ui.page("/generator")
def generator_page():
    # Protected page: no valid session → back to login
    session = current_session()
    if session is None:
        return RedirectResponse("/login")

    _apply_theme()
    _apply_user_theme()
    show_flash()

    vaults = load_vaults(session)
    vault_dialog = _create_vault_dialog(session)
    main_area = _app_shell(vaults, vault_dialog.open, active="generator", show_search=False)

    # Current options. Every change regenerates right away.
    state = {
        "mode": "password",
        "length": 20, "upper": True, "lower": True, "digits": True, "symbols": True,
        "words": 5, "separator": "-", "capitalize": True, "number": True,
        "result": "",
    }

    def regenerate():
        if state["mode"] == "password":
            state["result"] = generator.generate_password(
                state["length"], state["upper"], state["lower"], state["digits"], state["symbols"])
            pool = generator.password_pool_size(state["upper"], state["lower"], state["digits"], state["symbols"])
            bits = generator.entropy_bits(pool, state["length"])
        else:
            if not WORDLIST:
                state["result"] = ""
                result_label.set_text("Passphrases need the word list file. See core/wordlists/.")
                strength_label.set_text("")
                strength_bar.set_value(0)
                return
            state["result"] = generator.generate_passphrase(
                WORDLIST, state["words"], state["separator"], state["capitalize"], state["number"])
            bits = generator.entropy_bits(len(WORDLIST), state["words"])
            if state["number"]:
                bits += generator.entropy_bits(10, 1)

        result_label.set_text(state["result"])
        strength_label.set_text(f"{generator.strength_label(bits)} · {round(bits)} bits")
        strength_bar.set_value(min(bits / 128, 1))

    def set_option(key, value):
        state[key] = value
        regenerate()

    def toggle_char_set(key, switch, value):
        # Never allow all four character types to be turned off
        others_on = any(state[k] for k in ("upper", "lower", "digits", "symbols") if k != key)
        if not value and not others_on:
            ui.notify("Keep at least one kind of character.", type="warning")
            switch.set_value(True)
            return
        set_option(key, value)

    def set_mode(e):
        state["mode"] = e.value
        password_options.set_visibility(e.value == "password")
        passphrase_options.set_visibility(e.value == "passphrase")
        regenerate()

    with main_area:
        with ui.column().classes("w-full max-w-2xl gap-0"):
            ui.label("Password Generator").classes("text-3xl font-extrabold tracking-tight text-slate-900 mt-8")
            ui.label("Make a strong password or passphrase. Nothing here is saved.").classes("text-slate-500 mt-1")

            # ===== Result =====
            with ui.element("div").classes("gk-panel w-full p-6 mt-8"):
                with ui.row().classes("w-full items-center no-wrap gap-3"):
                    result_label = ui.label("").classes("gk-mono text-xl text-slate-900 flex-1 break-all")
                    ui.button(icon="content_copy", on_click=lambda: copy_password(state["result"]) if state["result"] else None) \
                        .props("flat round color=grey-7").tooltip("Copy")
                    ui.button(icon="refresh", on_click=regenerate) \
                        .props("flat round color=grey-7").tooltip("Generate another")
                strength_bar = ui.linear_progress(value=0, show_value=False).props("rounded color=green-7").classes("mt-5")
                strength_label = ui.label("").classes("text-sm font-semibold text-slate-600 mt-2")

            # ===== Mode =====
            ui.toggle({"password": "Password", "passphrase": "Passphrase"}, value="password", on_change=set_mode) \
                .props('no-caps unelevated color=transparent text-color=grey-8 toggle-color=primary toggle-text-color=white') \
                .classes("gk-segmented mt-6")

            # ===== Password options =====
            with ui.element("div").classes("gk-panel w-full p-6 mt-4") as password_options:
                with ui.row().classes("w-full items-center justify-between no-wrap"):
                    ui.label("Length").classes("gk-field-key")
                    length_value = ui.label(str(state["length"])).classes("font-semibold text-slate-900")
                ui.slider(min=generator.MIN_LENGTH, max=generator.MAX_LENGTH, value=state["length"],
                          on_change=lambda e: (length_value.set_text(str(int(e.value))),
                                               set_option("length", int(e.value)))) \
                    .props("color=green-7 label")
                with ui.element("div").classes("grid grid-cols-2 gap-x-6 gap-y-2 mt-4"):
                    upper = ui.switch("Uppercase (A–Z)", value=True,
                                      on_change=lambda e: toggle_char_set("upper", upper, e.value)).props("color=green-7")
                    lower = ui.switch("Lowercase (a–z)", value=True,
                                      on_change=lambda e: toggle_char_set("lower", lower, e.value)).props("color=green-7")
                    digits = ui.switch("Numbers (0–9)", value=True,
                                       on_change=lambda e: toggle_char_set("digits", digits, e.value)).props("color=green-7")
                    symbols = ui.switch("Symbols (!@#…)", value=True,
                                        on_change=lambda e: toggle_char_set("symbols", symbols, e.value)).props("color=green-7")

            # ===== Passphrase options =====
            with ui.element("div").classes("gk-panel w-full p-6 mt-4") as passphrase_options:
                with ui.row().classes("w-full items-center justify-between no-wrap"):
                    ui.label("Words").classes("gk-field-key")
                    words_value = ui.label(str(state["words"])).classes("font-semibold text-slate-900")
                ui.slider(min=generator.MIN_WORDS, max=generator.MAX_WORDS, value=state["words"],
                          on_change=lambda e: (words_value.set_text(str(int(e.value))),
                                               set_option("words", int(e.value)))) \
                    .props("color=green-7 label")
                with ui.row().classes("w-full items-center gap-6 mt-4"):
                    ui.select({"-": "Dash  ( - )", " ": "Space", ".": "Period  ( . )", "_": "Underscore  ( _ )"},
                              value="-", label="Separator",
                              on_change=lambda e: set_option("separator", e.value)) \
                        .props("outlined dense").classes("gk-input").style("width: 200px")
                    ui.switch("Capitalize words", value=True,
                              on_change=lambda e: set_option("capitalize", e.value)).props("color=green-7")
                    ui.switch("Add a number", value=True,
                              on_change=lambda e: set_option("number", e.value)).props("color=green-7")
            passphrase_options.set_visibility(False)

        _mobile_credit()

    regenerate()


@ui.page("/settings")
def settings_page():
    # Protected page: no valid session → back to login
    session = current_session()
    if session is None:
        return RedirectResponse("/login")

    _apply_theme()
    dark = _apply_user_theme()
    show_flash()

    vaults = load_vaults(session)
    profile = load_profile(session) or {"username": "", "email": ""}
    vault_dialog = _create_vault_dialog(session)
    main_area = _app_shell(vaults, vault_dialog.open, active="settings", show_search=False)

    def confirm_profile_change(new_username: str, new_email: str):
        # Ask for the master password before changing how they sign in
        with _dialog() as dialog, ui.card().classes("gk-dialog gap-0"):
            _dialog_header("verified_user", "Confirm it's you",
                           "Enter your master password to save these changes.")

            _field_label("Master password")
            password = ui.input(password=True, password_toggle_button=True) \
                .props("outlined autofocus").classes("gk-input w-full")

            async def submit():
                try:
                    await run.io_bound(do_update_profile, session, password.value or "", new_username, new_email)
                except auth.InvalidCredentialsError:
                    ui.notify("Incorrect password.", type="negative")
                    password.set_value("")
                    return
                except auth.UserExistsError:
                    ui.notify("That username or email is already taken.", type="negative")
                    dialog.close()
                    return
                except ValueError as e:
                    ui.notify(str(e), type="negative")
                    dialog.close()
                    return
                # Remember the saved values, so "nothing changed" works on the next save
                profile["username"] = new_username
                profile["email"] = new_email
                dialog.close()
                ui.notify("Profile updated", type="positive")

            password.on("keydown.enter", submit)
            _dialog_footer(dialog, "Confirm", submit)
        dialog.open()

    with main_area:
        with ui.column().classes("w-full max-w-2xl gap-0"):
            ui.label("Settings").classes("text-3xl font-extrabold tracking-tight text-slate-900")
            ui.label(f"Manage your account and how {APP_FULL_NAME} looks.").classes("text-slate-500 mt-1")

            # ===== Profile =====
            with ui.element("div").classes("gk-panel w-full p-6 mt-8"):
                _dialog_header("person_outline", "Profile", "Your username and email.")

                _field_label("Username")
                username = ui.input(value=profile["username"]).props("outlined").classes("gk-input w-full")
                with username.add_slot("prepend"):
                    ui.icon("person_outline").classes("text-slate-500")

                _field_label("Email")
                email = ui.input(value=profile["email"]).props("outlined").classes("gk-input w-full")
                with email.add_slot("prepend"):
                    ui.icon("mail_outline").classes("text-slate-500")
                ui.label("If you change your email, use the new one next time you sign in.") \
                    .classes("text-xs text-slate-500 mt-2")

                def save_profile():
                    # Only ask for the password if something actually changed
                    new_username = (username.value or "").strip()
                    new_email = (email.value or "").strip().lower()
                    if new_username == profile["username"] and new_email == profile["email"]:
                        ui.notify("Nothing to change.")
                        return
                    confirm_profile_change(new_username, new_email)

                with ui.row().classes("w-full justify-end mt-6"):
                    ui.button("Save changes", on_click=save_profile) \
                        .props("unelevated no-caps").classes("rounded-lg px-5 font-semibold gradient-bg")

            # ===== Master password =====
            with ui.element("div").classes("gk-panel w-full p-6 mt-6"):
                _dialog_header("lock_outline", "Master password",
                               "Changing it keeps all your vaults and entries.")

                _field_label("Current password")
                current_pw = ui.input(password=True, password_toggle_button=True) \
                    .props("outlined").classes("gk-input w-full")

                with ui.element("div").classes("grid grid-cols-1 sm:grid-cols-2 gap-x-4 w-full"):
                    with ui.column().classes("gap-0 w-full"):
                        _field_label("New password")
                        new_pw = ui.input(password=True, password_toggle_button=True) \
                            .props("outlined").classes("gk-input w-full")
                    with ui.column().classes("gap-0 w-full"):
                        _field_label("Confirm new password")
                        confirm_pw = ui.input(password=True, password_toggle_button=True) \
                            .props("outlined").classes("gk-input w-full")

                ui.label("If you forget your master password, you'll need your recovery code to reset it.") \
                    .classes("text-xs text-slate-500 mt-2")

                async def change_password():
                    if (new_pw.value or "") != (confirm_pw.value or ""):
                        ui.notify("New passwords do not match.", type="negative")
                        return
                    if new_pw.value == current_pw.value:
                        ui.notify("New password must be different from the current one.", type="negative")
                        return
                    try:
                        await run.io_bound(do_change_password, session, current_pw.value or "", new_pw.value or "")
                    except auth.InvalidCredentialsError:
                        ui.notify("Current password is incorrect.", type="negative")
                        return
                    except auth.PasswordComplexityError:
                        ui.notify("Password must be at least 12 and no more than 256 characters long.", type="negative")
                        return
                    # Clear the fields so the passwords don't sit on screen
                    for field in (current_pw, new_pw, confirm_pw):
                        field.set_value("")
                    # This session ended too, so sign in again with the new password
                    app.storage.user.pop("token", None)
                    app.storage.user["flash"] = "Master password changed. Sign in again with your new password."
                    ui.navigate.to("/login")

                with ui.row().classes("w-full justify-end mt-6"):
                    ui.button("Change password", on_click=change_password) \
                        .props("unelevated no-caps").classes("rounded-lg px-5 font-semibold gradient-bg")

            # ===== Recovery code =====
            has_code = {"value": load_has_recovery_code(session)}

            @ui.refreshable
            def recovery_panel():
                with ui.element("div").classes("gk-panel w-full p-6 mt-6"):
                    _dialog_header("key", "Recovery code", "Your way back in if you forget your master password.")
                    if has_code["value"]:
                        ui.label("You have a recovery code. We never store it, so we can't show it again. "
                                 "Create a new one if you lost it. Your old one will stop working.") \
                            .classes("text-sm text-slate-600 mt-4")
                    else:
                        ui.label("You don't have a recovery code yet. Create one so you can reset your "
                                 "master password if you forget it.") \
                            .classes("text-sm text-slate-600 mt-4")
                    with ui.row().classes("w-full justify-end mt-6"):
                        ui.button("Create new recovery code", icon="autorenew", on_click=confirm_new_code) \
                            .props("unelevated no-caps").classes("rounded-lg px-5 font-semibold gradient-bg")

            def confirm_new_code():
                # Ask for the master password, then show the new code once
                with _dialog() as dialog, ui.card().classes("gk-dialog gap-0"):
                    _dialog_header("verified_user", "Confirm it's you",
                                   "Enter your master password to create a new recovery code.")
                    _field_label("Master password")
                    pw = ui.input(password=True, password_toggle_button=True) \
                        .props("outlined autofocus").classes("gk-input w-full")

                    async def submit():
                        try:
                            new_code = await run.io_bound(do_create_recovery_code, session.user_id, pw.value or "")
                        except auth.InvalidCredentialsError:
                            ui.notify("Incorrect password.", type="negative")
                            pw.set_value("")
                            return
                        dialog.close()

                        def done():
                            has_code["value"] = True
                            recovery_panel.refresh()
                            ui.notify("New recovery code saved. Your old one no longer works.", type="positive")

                        _open_recovery_code_dialog(new_code, profile["email"], done)

                    pw.on("keydown.enter", submit)
                    _dialog_footer(dialog, "Continue", submit)
                dialog.open()

            recovery_panel()

            # ===== Import & export =====
            with ui.element("div").classes("gk-panel w-full p-6 mt-6"):
                _dialog_header("import_export", "Import & export",
                               "Move your logins in or out with a CSV file.")

                editable = [(v.vault_id, v.name) for v, _count in vaults if v.can_edit]
                all_vault_options = {v.vault_id: v.name for v, _count in vaults}

                # --- Export ---
                ui.label("Export").classes("gk-field-key mt-6")
                export_scope = ui.select({"__all__": "All passwords", **all_vault_options}, value="__all__",
                                         label="What to export").props("outlined dense").classes("gk-input w-full mt-2")

                def open_export():
                    with _dialog() as dialog, ui.card().classes("gk-dialog gap-0"):
                        _dialog_header("warning_amber", "Export to CSV",
                                       "The file is NOT encrypted. Anyone who opens it can read every password.",
                                       tone="red")
                        ui.label("Import it where you need it, then delete it. Don't open it in Excel, "
                                 "and don't email it or store it in the cloud.").classes("text-sm text-slate-600 mt-4")
                        _field_label("Master password")
                        pw = ui.input(password=True, password_toggle_button=True) \
                            .props("outlined autofocus").classes("gk-input w-full")

                        async def submit():
                            scope = None if export_scope.value == "__all__" else export_scope.value
                            try:
                                csv_text = await run.io_bound(do_export_csv, session, pw.value or "", scope)
                            except auth.InvalidCredentialsError:
                                ui.notify("Incorrect password.", type="negative")
                                pw.set_value("")
                                return
                            dialog.close()
                            filename = f"grishakey-export-{datetime.now().strftime('%Y-%m-%d')}.csv"
                            ui.download.content(csv_text, filename)
                            ui.notify("Export downloaded. Delete the file when you're done with it.", type="positive")

                        pw.on("keydown.enter", submit)
                        _dialog_footer(dialog, "Download CSV", submit, danger=True)
                    dialog.open()

                with ui.row().classes("w-full justify-end mt-3"):
                    ui.button("Export CSV", icon="download", on_click=open_export) \
                        .props("outline no-caps color=grey-8").classes("rounded-lg px-5 font-semibold")

                # --- Import ---
                ui.label("Import").classes("gk-field-key mt-8")
                if not editable:
                    ui.label("You need a vault you can edit to import into.").classes("text-sm text-slate-500 mt-2")
                else:
                    target = ui.select(dict(editable), value=editable[0][0], label="Import into") \
                        .props("outlined dense").classes("gk-input w-full mt-2")
                    ui.label("Works with CSV files from GrishaKey, Bitwarden, NordPass, 1Password, Chrome, and Firefox.") \
                        .classes("text-xs text-slate-500 mt-2")

                    async def handle_upload(e):
                        # Read the uploaded file into memory only (never saved to disk)
                        data = await e.file.read()
                        try:
                            rows, skipped = transfer.parse_csv(data)
                        except ValueError as err:
                            ui.notify(str(err), type="negative")
                            uploader.reset()
                            return
                        uploader.reset()
                        confirm_import(rows, skipped)

                    def on_rejected():
                        # The browser refused the file before sending it (over the size limit)
                        ui.notify("That file is too large. The limit is 2 MB.", type="negative")

                    def confirm_import(rows, skipped):
                        vault_name = all_vault_options.get(target.value, "this vault")
                        with _dialog() as dialog, ui.card().classes("gk-dialog gap-0"):
                            _dialog_header("upload_file", "Import logins",
                                           f'{len(rows)} login{"" if len(rows) == 1 else "s"} found'
                                           + (f", {skipped} empty row{'' if skipped == 1 else 's'} skipped" if skipped else "")
                                           + f'. They\'ll be added to "{vault_name}".')
                            for row in rows[:5]:
                                ui.label(f'{row["title"]}  ·  {row["username"] or "no username"}') \
                                    .classes("text-sm text-slate-700 mt-2 truncate")
                            if len(rows) > 5:
                                ui.label(f"…and {len(rows) - 5} more").classes("text-sm text-slate-500 mt-1")
                            ui.label("After importing, delete the CSV file from your computer.") \
                                .classes("text-sm text-slate-500 mt-4")

                            async def submit():
                                try:
                                    added = await run.io_bound(do_import_rows, session, target.value, rows)
                                except (ValueError, PermissionError) as err:
                                    ui.notify(str(err), type="negative")
                                    return
                                dialog.close()
                                app.storage.user["flash"] = f'Imported {added} login{"" if added == 1 else "s"} into "{vault_name}"'
                                ui.navigate.to(f"/vault/{target.value}")

                            _dialog_footer(dialog, "Import", submit)
                        dialog.open()

                    uploader = ui.upload(on_upload=handle_upload, on_rejected=on_rejected, auto_upload=True,
                                         max_files=1, max_file_size=transfer.MAX_IMPORT_BYTES,
                                         label="Choose a CSV file") \
                        .props('accept=".csv,text/csv" flat bordered').classes("w-full mt-3")

            # ===== Appearance =====
            with ui.element("div").classes("gk-panel w-full p-6 mt-6"):
                _dialog_header('palette', 'Appearance', 'Choose how the app looks.')

                def set_theme(e):
                    # Save the choice, and switch right away
                    app.storage.user["theme"] = e.value
                    dark.set_value(THEMES[e.value])

                ui.toggle({"light": "Light", "dark": "Dark", "auto": "System"},
                          value=app.storage.user.get("theme", "light"), on_change=set_theme) \
                    .props('no-caps unelevated color=transparent text-color=grey-8 toggle-color=primary toggle-text-color=white') \
                    .classes("gk-segmented mt-5")

            # ===== Sign out =====
            with ui.element("div").classes("gk-panel w-full p-6 mt-6 mb-10"):
                with ui.row().classes("w-full items-center justify-between no-wrap gap-4"):
                    _dialog_header("logout", "Sign out", "End your session on this device.", tone="red")
                    ui.button("Log out", on_click=logout) \
                        .props("outline no-caps color=negative").classes("rounded-lg px-5 font-semibold")

        _mobile_credit()


@ui.page("/help")
def help_page():
    # Protected page: no valid session → back to login
    session = current_session()
    if session is None:
        return RedirectResponse("/login")

    _apply_theme()
    _apply_user_theme()
    show_flash()

    vaults = load_vaults(session)
    vault_dialog = _create_vault_dialog(session)
    main_area = _app_shell(vaults, vault_dialog.open, active="help", show_search=False)

    sections = [
        ("start", "Getting started"),
        ("organize", "Organizing vaults"),
        ("people", "Adding & removing people"),
        ("share-entry", "Sharing one entry"),
        ("everyday", "Passwords, Trash & Generator"),
        ("security", "Security"),
        ("faq", "FAQ"),
    ]

    with main_area:
        with ui.column().classes("w-full max-w-3xl gap-0 pb-16"):
            ui.label("Help").classes("text-3xl font-extrabold tracking-tight text-slate-900 mt-8")
            ui.label(f"Learn {APP_FULL_NAME} in a few minutes.").classes("text-slate-500 mt-1")

            # Quick-jump chips
            with ui.row().classes("gap-2 mt-6"):
                for section_id, name in sections:
                    ui.label(name).classes("gk-help-chip").on("click", lambda s=section_id: _scroll_to(s))

            # ===== Getting started =====
            with _help_section("start", "rocket_launch", "Getting started"):
                _help_steps([
                    "Create a vault: open Vaults in the sidebar and click Create Vault.",
                    "Add an entry: open the vault and click Add entry.",
                    "Copy a password: click the key icon on any entry. Your clipboard clears after 30 seconds.",
                    "Need a new password? Use the Password Generator at the bottom of the sidebar.",
                ])

            # ===== Organizing vaults =====
            with _help_section("organize", "o_folder_copy", "Organizing vaults"):
                _help_points([
                    "Make vaults around WHO needs access, not what the password is for.",
                    "Put logins everyone needs in one shared vault, like Band.",
                    "People can be in more than one vault.",
                ])
                _help_diagram("""graph LR
    Kim([Kim · trombone]) --> T[Trombones]
    Kim --> B[Band · everyone]
    Ana([Ana · saxophone]) --> S[Saxophones]
    Ana --> B
    Lee([Lee · flute]) --> F[Flutes]
    Lee --> B""")

            # ===== Adding & removing people =====
            with _help_section("people", "group_add", "Adding & removing people"):
                _help_steps([
                    "Open the vault and click Share.",
                    "Type their email. They need an account first.",
                    "Pick Can view or Can edit, then click Add.",
                    "To remove someone, click the X next to their name and confirm.",
                ])
                ui.label("Roles").classes("gk-field-key mt-3")
                for pill, pill_class, text in [
                    ("Owner", "gk-pill gk-pill-green", "Everything: add and remove people, share, and move entries to Trash."),
                    ("Can edit", "gk-pill", "Add and change entries."),
                    ("Can view", "gk-pill", "See and copy entries only."),
                ]:
                    with ui.row().classes("items-center gap-3 no-wrap"):
                        ui.label(pill).classes(pill_class).style("min-width: 76px; text-align: center")
                        ui.label(text).classes("text-slate-700")
                ui.label(
                    "When you remove someone, they lose access right away, and the vault's keys change "
                    "so old copies stop working. If they saw important passwords, change those too."
                ).classes("text-sm text-slate-500 mt-2")

            # ===== Sharing one entry =====
            with _help_section("share-entry", "person_add_alt", "Sharing one entry"):
                _help_points([
                    "Share one login without giving access to the whole vault.",
                    "Open the entry, or use the share icon on its row, and click Share.",
                    "Use this for one-offs. If a group needs many logins, share a vault instead.",
                ])
                _help_diagram("""graph LR
    V[Work vault] -- Share vault --> K([Kim: every entry, now and later])
    E[Wi-Fi entry] -- Share entry --> A([Amy: just this one])""")

            # ===== Passwords, Trash & Generator =====
            with _help_section("everyday", "key", "Passwords, Trash & Generator"):
                _help_points([
                    "Passwords: every login you can open, in one list. Filter by Shared with me and sort A to Z.",
                    "Trash: moved entries wait here. Restore them, or delete them forever. Only the vault owner sees them.",
                    "Password Generator: make strong passwords or passphrases. Longer is stronger.",
                ])

            # ===== Security =====
            with _help_section("security", "shield", "Security"):
                _help_points([
                    f"Everything is locked (encrypted) before it's saved. {APP_FULL_NAME} only stores locked data.",
                    "Your master password is never stored. It's the only key that unlocks your account.",
                    "Each vault and entry has its own key, so sharing one never reveals anything else.",
                ])
                _help_diagram("""graph LR
    P[Master password<br/>only you know it] --> K[Unlocks your<br/>personal key]
    K --> V[Unlocks your<br/>vault keys]
    V --> E[Unlocks your<br/>entries]""")

            # ===== FAQ =====
            with _help_section("faq", "quiz", "FAQ"):
                for question, answer in [
                    ("I forgot my master password. Can it be reset?",
                     "Yes, with your recovery code. Click \"Forgot your password?\" on the sign-in page, "
                     f"enter your email and recovery code, and pick a new password. Without the code, no one "
                     f"can reset it, including admins, because {APP_FULL_NAME} never stores your password. "
                     "Lost your code? Create a new one in Settings while you're signed in."),
                    ("How does the encryption work?",
                     "Your master password creates a key that only exists while you're signed in. That key "
                     "unlocks your personal key, which unlocks your vaults, which unlock your entries. "
                     "The server only ever holds the locked versions."),
                    ("What happens when I remove someone?",
                     "They lose access right away, and the keys change so any old copies stop working. "
                     "If they saw important passwords, change those too."),
                    ("Why can't I edit, share, or delete something?",
                     "It depends on your role. View-only members can't edit. Only the vault owner can share, "
                     "remove people, or move entries to Trash."),
                    ("Share a vault or share an entry?",
                     "Share a vault when a group needs many logins. Share an entry for a single login or a single person."),
                    ("Where did my deleted entry go?",
                     "To the Trash. The vault owner can restore it until the Trash is emptied."),
                    ("How do I change my email, username, or password?",
                     "Go to Settings. Changing your email or username asks for your master password first."),
                    ("How do I move my passwords in or out?",
                     "Go to Settings, then Import & export. Export makes a CSV file (not encrypted, so delete it "
                     "after use). Import accepts CSV files from most password managers."),
                ]:
                    with ui.expansion(question).classes("w-full gk-faq"):
                        ui.label(answer).classes("text-slate-700")

        _mobile_credit()


# ========== Run ==========

# NiceGUI recommends this check so the app only starts once
if __name__ in {"__main__", "__mp_main__"}:
    ui.run(
        host=HOST,
        port=PORT,
        title=f"{APP_FULL_NAME}",
        favicon=BASE_DIR / "assets" / "favicon.png",
        storage_secret=STORAGE_SECRET,
        reload=False,
    )
# GrishaKey browser extension (Stage 1)

Find and copy your GrishaKey logins for the site you're on.

## Load it in Chrome or Edge

1. Open `chrome://extensions` (or `edge://extensions`).
2. Turn on **Developer mode**.
3. Click **Load unpacked** and pick this `extension` folder.
4. Open the extension's **Options**, enter your server (for example `http://127.0.0.1:9500`), and allow access.
5. Click the GrishaKey icon on any site to sign in and see its logins.

## How it stays safe

- Signs in with your master password and gets a short-lived token, kept in memory only.
- Only shows logins whose saved site matches the page (lookalike domains never match).
- Passwords are fetched one at a time, only when you click copy.
- Only talks to the one server you set, and requires HTTPS unless it's on this computer.

## Fill from login fields (optional)

Turn on **Show GrishaKey in login fields** in the extension's Options. A GrishaKey icon appears in
password fields; click it, pick a login, and it's filled in. Your browser asks for access to all
websites, because the icon has to appear on them. The websites themselves never see your logins:
the list is drawn by the extension in a sealed frame, and a login is only filled after you click it,
only into visible fields, and only on the site it belongs to.

Note: copied passwords aren't cleared from the clipboard automatically yet.

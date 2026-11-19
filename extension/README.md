# GrishaKey browser extension

Finds your GrishaKey logins for the site you're on, fills them with a click, and lets you save
new ones without opening the app. Works in Chrome, Edge, and Brave.

For installing, connecting it to your server, and turning on filling from login fields, see
[Browser extension](../README.md#browser-extension) in the main README.

## How it stays safe

- Your sign-in token is kept in memory only, and ends after 15 minutes without use.
- Logins only show on their own site. Lookalike domains (like `githuub.com`) never match.
- Passwords are fetched one at a time, only when you click.
- The list of logins is drawn by the extension in a sealed frame the website can't read.
- Filling only happens when you click, only into visible fields.
- It only sends your data to the server you set. Filling from login fields adds access to websites
  so the icon can appear on them, but nothing is sent to those websites.

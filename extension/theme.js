// Applies the saved theme ("light" or "dark") to this page. No saved theme → follow the system.
// Loaded in <head> on every extension page, so the right colors show as early as possible.
(async () => {
  const root = document.documentElement;
  const apply = (theme) => {
    if (theme === "light" || theme === "dark") root.dataset.theme = theme;
    else delete root.dataset.theme;
  };
  const { theme } = await chrome.storage.local.get("theme");
  apply(theme);
  // Keep every open GrishaKey page in sync when the theme changes
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.theme) apply(changes.theme.newValue);
  });
})();

// Used by the theme button: switch to the opposite of what's showing now
async function toggleTheme() {
  const root = document.documentElement;
  const current = root.dataset.theme ||
    (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  const next = current === "dark" ? "light" : "dark";
  root.dataset.theme = next;
  await chrome.storage.local.set({ theme: next });
}

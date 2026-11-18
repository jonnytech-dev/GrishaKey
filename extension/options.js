// Saves the server address and asks the browser for access to ONLY that server.
const input = document.getElementById("server");
const result = document.getElementById("result");

function clean(address) {
  const url = new URL(address.trim());
  const local = ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname);
  // Real servers must use HTTPS; plain http is only allowed on this computer
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) {
    throw new Error("Use https:// (http:// is only allowed for 127.0.0.1 or localhost).");
  }
  return url.origin;
}

chrome.storage.local.get("server").then(({ server }) => {
  if (server) input.value = server;
});

document.getElementById("save").addEventListener("click", async () => {
  result.classList.remove("error");
  try {
    const origin = clean(input.value);
    const granted = await chrome.permissions.request({ origins: [`${origin}/*`] });
    if (!granted) throw new Error("Access wasn't allowed, so the extension can't reach the server.");
    await chrome.storage.local.set({ server: origin });
    await chrome.storage.session.remove("token");
    result.textContent = "Saved. Open the GrishaKey popup to sign in.";
  } catch (err) {
    result.textContent = err.message;
    result.classList.add("error");
  }
});

// Opt-in: in-page autofill needs access to all websites, so it's off until the user turns it on
const inlineBox = document.getElementById("inline");
const inlineResult = document.getElementById("inline-result");

chrome.storage.local.get("inlineEnabled").then(({ inlineEnabled }) => {
  inlineBox.checked = Boolean(inlineEnabled);
});

inlineBox.addEventListener("change", async () => {
  inlineResult.classList.remove("error");
  try {
    if (inlineBox.checked) {
      const granted = await chrome.permissions.request({ origins: ["http://*/*", "https://*/*"] });
      if (!granted) throw new Error("Access wasn't allowed, so the icon can't appear on websites.");
    }
    const reply = await chrome.runtime.sendMessage({ type: "gk-set-inline", enabled: inlineBox.checked });
    if (reply?.error) throw new Error(reply.error);
    inlineResult.textContent = inlineBox.checked
      ? "On. Reload any open login pages to see the icon."
      : "Off. The icon won't appear on websites.";
  } catch (err) {
    inlineBox.checked = false;
    inlineResult.textContent = err.message;
    inlineResult.classList.add("error");
  }
});

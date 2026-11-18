// GrishaKey background service worker.
// Holds the sign-in token, talks to the API, and decides what may be filled where.

const CONTENT_SCRIPT_ID = "gk-inline";

async function getServer() {
  const { server } = await chrome.storage.local.get("server");
  return server || null;
}

async function getToken() {
  const { token } = await chrome.storage.session.get("token");
  return token || null;
}

async function api(path, options = {}) {
  const server = await getServer();
  const token = await getToken();
  if (!server || !token) throw new Error("signed-out");
  let response;
  try {
    response = await fetch(`${server}/api/v1${path}`, {
      method: options.method || "GET",
      headers: { Authorization: `Bearer ${token}` },
    });
  } catch {
    throw new Error("Can't reach your GrishaKey server.");
  }
  if (response.status === 401) {
    await chrome.storage.session.remove("token");
    throw new Error("signed-out");
  }
  if (!response.ok) throw new Error(`Request failed (${response.status})`);
  return response.json();
}

// Which field was clicked, per tab. Kept in session storage (the service worker can sleep).
// Only ever written from a content script's message, using the browser-reported sender details.
async function setContext(tabId, context) {
  await chrome.storage.session.set({ [`ctx-${tabId}`]: context });
}
async function getContext(tabId) {
  const key = `ctx-${tabId}`;
  return (await chrome.storage.session.get(key))[key] || null;
}

// Turn the in-page icon on or off (called from the Options page)
async function setInline(enabled) {
  const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [CONTENT_SCRIPT_ID] });
  if (enabled && existing.length === 0) {
    await chrome.scripting.registerContentScripts([{
      id: CONTENT_SCRIPT_ID,
      js: ["content.js"],
      matches: ["http://*/*", "https://*/*"],
      allFrames: true,
      runAt: "document_idle",
    }]);
  }
  if (!enabled && existing.length > 0) {
    await chrome.scripting.unregisterContentScripts({ ids: [CONTENT_SCRIPT_ID] });
  }
  await chrome.storage.local.set({ inlineEnabled: enabled });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    // Messages from the in-page dropdown must come from our own inline.html frame
    const fromInline = sender.id === chrome.runtime.id &&
      (sender.url || "").startsWith(chrome.runtime.getURL("inline.html"));
    try {
      // From content.js: a GrishaKey icon was clicked in this frame
      if (message.type === "gk-open") {
        if (!sender.tab || sender.frameId === undefined) throw new Error("No tab");
        await setContext(sender.tab.id, { frameId: sender.frameId, url: sender.url });
        sendResponse({ ok: true });
        return;
      }

      // From inline.js (the dropdown): which logins match the clicked frame's site?
      if (message.type === "gk-get-logins") {
        const ctx = sender.tab ? await getContext(sender.tab.id) : null;
        if (!ctx) throw new Error("Click the GrishaKey icon in a login field first.");
        if (!(await getToken())) {
          sendResponse({ signedIn: false });
          return;
        }
        const host = new URL(ctx.url).hostname;
        const logins = await api(`/logins?url=${encodeURIComponent(ctx.url)}`);
        sendResponse({ signedIn: true, host, logins });
        return;
      }

      // From inline.js: fill this login into the clicked field
      if (message.type === "gk-fill") {
        const ctx = sender.tab ? await getContext(sender.tab.id) : null;
        if (!ctx) throw new Error("Click the GrishaKey icon in a login field first.");

        // Re-check that this login really matches the clicked frame's site
        const logins = await api(`/logins?url=${encodeURIComponent(ctx.url)}`);
        const login = logins.find((l) => l.id === message.entryId);
        if (!login) throw new Error("That login doesn't match this site.");

        const { password } = await api(`/logins/${encodeURIComponent(login.id)}/password`);
        await chrome.tabs.sendMessage(
          sender.tab.id,
          { type: "gk-fill", username: login.username, password },
          { frameId: ctx.frameId },
        );
        sendResponse({ ok: true });
        return;
      }

      // From inline.js: close the dropdown
      if (message.type === "gk-close") {
        const ctx = sender.tab ? await getContext(sender.tab.id) : null;
        if (ctx) await chrome.tabs.sendMessage(sender.tab.id, { type: "gk-close" }, { frameId: ctx.frameId });
        sendResponse({ ok: true });
        return;
      }

      // From inline.js: open the form in a small extension window
      if (message.type === "gk-open-editor") {
        if (!fromInline) throw new Error("Not allowed");
        const ctx = sender.tab ? await getContext(sender.tab.id) : null;
        if (!ctx) throw new Error("Click the GrishaKey icon in a login field first.");
        const params = new URLSearchParams({ site: new URL(ctx.url).origin });
        if (message.mode === "edit") {
          // Only logins that match the clicked site can be opened from this page
          const logins = await api(`/logins?url=${encodeURIComponent(ctx.url)}`);
          const login = logins.find((l) => l.id === message.entryId);
          if (!login || !login.can_edit) throw new Error("That login can't be edited here.");
          params.set("mode", "edit");
          params.set("id", login.id);
        } else {
          params.set("mode", "new");
        }
        await chrome.windows.create({
          url: chrome.runtime.getURL(`popup.html?${params}`),
          type: "popup", width: 400, height: 680,
        });
        sendResponse({ ok: true });
        return;
      }

      // From inline.js: move a login to the Trash
      if (message.type === "gk-delete") {
        if (!fromInline) throw new Error("Not allowed");
        const ctx = sender.tab ? await getContext(sender.tab.id) : null;
        if (!ctx) throw new Error("Click the GrishaKey icon in a login field first.");
        const logins = await api(`/logins?url=${encodeURIComponent(ctx.url)}`);
        const login = logins.find((l) => l.id === message.entryId);
        if (!login || !login.can_delete) throw new Error("That login can't be deleted here.");
        await api(`/logins/${encodeURIComponent(login.id)}`, { method: "DELETE" });
        sendResponse({ ok: true });
        return;
      }

      // From options.js (an extension page): turn the in-page icon on or off
      if (message.type === "gk-set-inline") {
        // Only the extension's own pages (like Options) may change this, never a website.
        // A content script on a website has the website's URL here; extension pages have ours.
        const fromExtensionPage = sender.id === chrome.runtime.id &&
          (sender.url || "").startsWith(chrome.runtime.getURL(""));
        if (!fromExtensionPage) throw new Error("Not allowed");
        await setInline(Boolean(message.enabled));
        sendResponse({ ok: true });
        return;
      }

      sendResponse({ error: "Unknown request" });
    } catch (err) {
      sendResponse({ error: err.message === "signed-out" ? "signed-out" : err.message });
    }
  })();
  return true;   // keep the channel open for the async reply
});

// Forget a tab's context when it closes
chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove(`ctx-${tabId}`));

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

// The stored context, but only while our own dropdown is really open in the clicked frame.
// Any website can frame inline.html (it's web-accessible), and the stored context outlives a
// navigation, so a page the tab moved on to could otherwise act on the previous site's logins.
// The clicked frame's content script knows whether it opened a dropdown; a new page's doesn't.
async function getOpenContext(tabId) {
  const ctx = await getContext(tabId);
  if (!ctx) return null;
  try {
    const reply = await chrome.tabs.sendMessage(tabId, { type: "gk-ping" }, { frameId: ctx.frameId });
    return reply?.open ? ctx : null;
  } catch {
    return null;     // the frame is gone, or has no content script
  }
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
    // Messages from content.js come from a website frame in a tab (never an extension page)
    const fromContentScript = sender.id === chrome.runtime.id && Boolean(sender.tab) &&
      /^https?:\/\//.test(sender.url || "");
    try {
      // From content.js: a GrishaKey icon was clicked in this frame
      if (message.type === "gk-open") {
        if (!fromContentScript) throw new Error("Not allowed");
        if (!sender.tab || sender.frameId === undefined) throw new Error("No tab");
        await setContext(sender.tab.id, { frameId: sender.frameId, url: sender.url });
        sendResponse({ ok: true });
        return;
      }

      // From inline.js (the dropdown): which logins match the clicked frame's site?
      if (message.type === "gk-get-logins") {
        if (!fromInline) throw new Error("Not allowed");
        const ctx = sender.tab ? await getOpenContext(sender.tab.id) : null;
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

      // From inline.js: search every login. The site to compare against comes from the stored context.
      if (message.type === "gk-search") {
        if (!fromInline) throw new Error("Not allowed");
        const ctx = sender.tab ? await getOpenContext(sender.tab.id) : null;
        if (!ctx) throw new Error("Click the GrishaKey icon in a login field first.");
        const q = typeof message.q === "string" ? message.q.trim().slice(0, 100) : "";
        if (!q) { sendResponse({ results: [] }); return; }
        // Only the page's origin is sent: matching uses the host, and long addresses stay under the limit
        const results = await api(`/logins/search?q=${encodeURIComponent(q)}&url=${encodeURIComponent(new URL(ctx.url).origin)}`);
        sendResponse({ results });
        return;
      }

      // From inline.js: fill this login into the clicked field
      if (message.type === "gk-fill") {
        if (!fromInline) throw new Error("Not allowed");
        const ctx = sender.tab ? await getOpenContext(sender.tab.id) : null;
        if (!ctx) throw new Error("Click the GrishaKey icon in a login field first.");

        // Re-check that this login really matches the clicked frame's site
        const logins = await api(`/logins?url=${encodeURIComponent(ctx.url)}`);
        let login = logins.find((l) => l.id === message.entryId);
        // A search result saved for another site: inline.js asked the user to confirm first.
        // Look it up again on the server (the site still comes from the stored context).
        if (!login && message.allowOtherSite === true && typeof message.title === "string") {
          const q = message.title.trim().slice(0, 100);
          if (q) {
            const results = await api(`/logins/search?q=${encodeURIComponent(q)}&url=${encodeURIComponent(new URL(ctx.url).origin)}`);
            login = results.find((l) => l.id === message.entryId);
          }
        }
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
        if (!fromInline) throw new Error("Not allowed");
        const ctx = sender.tab ? await getContext(sender.tab.id) : null;
        if (ctx) await chrome.tabs.sendMessage(sender.tab.id, { type: "gk-close" }, { frameId: ctx.frameId });
        sendResponse({ ok: true });
        return;
      }

      // From inline.js: open the form in a small extension window
      if (message.type === "gk-open-editor") {
        if (!fromInline) throw new Error("Not allowed");
        const ctx = sender.tab ? await getOpenContext(sender.tab.id) : null;
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
        const ctx = sender.tab ? await getOpenContext(sender.tab.id) : null;
        if (!ctx) throw new Error("Click the GrishaKey icon in a login field first.");
        const logins = await api(`/logins?url=${encodeURIComponent(ctx.url)}`);
        const login = logins.find((l) => l.id === message.entryId);
        if (!login || !login.can_delete) throw new Error("That login can't be deleted here.");
        await api(`/logins/${encodeURIComponent(login.id)}`, { method: "DELETE" });
        sendResponse({ ok: true });
        return;
      }

      // From inline.js: sign in from the in-page dropdown.
      // The dropdown never keeps the token; it's stored here, in memory-only session storage.
      if (message.type === "gk-login") {
        if (!fromInline) throw new Error("Not allowed");
        const email = typeof message.email === "string" ? message.email.slice(0, 320) : "";
        const password = typeof message.password === "string" ? message.password.slice(0, 256) : "";
        const server = await getServer();
        if (!server) throw new Error("Set your GrishaKey server in the extension's Options first.");
        let response;
        try {
          response = await fetch(`${server}/api/v1/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password }),
          });
        } catch {
          throw new Error("Can't reach your GrishaKey server.");
        }
        if (response.status === 401) throw new Error("Incorrect email or password");
        if (!response.ok) {
          const body = await response.json().catch(() => ({}));
          throw new Error(typeof body.detail === "string" ? body.detail : "Sign-in failed. Try again.");
        }
        const { token } = await response.json();
        await chrome.storage.session.set({ token, email });
        sendResponse({ ok: true });
        return;
      }

      // From inline.js: resize the dropdown frame to fit its content
      if (message.type === "gk-resize") {
        if (!fromInline) throw new Error("Not allowed");
        const ctx = sender.tab ? await getContext(sender.tab.id) : null;
        const height = Math.max(140, Math.min(460, Number(message.height) || 320));
        if (ctx) await chrome.tabs.sendMessage(sender.tab.id, { type: "gk-resize", height }, { frameId: ctx.frameId });
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

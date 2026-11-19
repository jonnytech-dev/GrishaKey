// GrishaKey popup: sign in, show logins for the current site, copy on click.
// Server data is only ever put on the page with textContent (never innerHTML).

const $ = (id) => document.getElementById(id);

// Opened as a separate window from the in-page dropdown (Edit or + New login)
const pageParams = new URLSearchParams(location.search);
const windowMode = pageParams.get("mode");            // "new", "edit", or null (normal popup)
const show = (id) => {
  const el = $(id);
  el.classList.remove("hidden");
  el.classList.remove("fade-in");
  void el.offsetWidth;            // restart the animation
  el.classList.add("fade-in");
};
const hide = (id) => $(id).classList.add("hidden");

// Clone a fixed SVG icon from the <template>s in popup.html (never server data)
const icon = (name) => document.getElementById(`icon-${name}`).content.firstElementChild.cloneNode(true);
const setIcon = (id, name) => $(id).replaceChildren(icon(name));

// Which header shows: "home" (logo bar), "form" (back + title), or none (sign in / setup)
function setHeader(kind) {
  $("topbar").classList.toggle("hidden", kind !== "home");
  $("formbar").classList.toggle("hidden", kind !== "form");
}

// Short confirmation at the bottom ("Password copied", "Login saved")
let toastTimer = null;
function showToast(text) {
  $("toast-text").textContent = text;
  show("toast");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => hide("toast"), 3000);
}

// The avatar shows the first letter of the signed-in email (kept in memory-only session storage)
async function updateAvatar() {
  const { email } = await chrome.storage.session.get("email");
  $("avatar").textContent = (email || "?").charAt(0).toUpperCase();
  $("avatar").title = email || "";
}

// Theme button: sun when dark is showing (click → light), moon when light is showing
function updateThemeIcon() {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === "dark"
    : !window.matchMedia("(prefers-color-scheme: light)").matches;
  setIcon("theme-toggle", dark ? "sun" : "moon");
}

async function getServer() {
  const { server } = await chrome.storage.local.get("server");
  return server || null;
}

// The token lives in session storage: memory only, gone when the browser closes
async function getToken() {
  const { token } = await chrome.storage.session.get("token");
  return token || null;
}

async function api(path, options = {}) {
  const server = await getServer();
  const token = await getToken();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  let response;
  try {
    response = await fetch(`${server}/api/v1${path}`, { ...options, headers });
  } catch {
    throw new Error("Can't reach your GrishaKey server. Check the address in Settings.");
  }
  if (response.status === 401) {
    await chrome.storage.session.remove("token");
    throw new Error("signed-out");
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    let detail = body.detail;
    if (Array.isArray(detail)) {
      detail = detail[0]?.msg ? `Check the form: ${detail[0].msg}` : "Check the form and try again.";
    }
    throw new Error(detail || `Request failed (${response.status})`);
  }
  return response.json();
}

async function currentTabUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url || "";
}

function setStatus(text, isError = false) {
  const status = $("status");
  status.textContent = text;
  status.classList.toggle("error", isError);
  show("status");
}

async function copyText(text, label) {
  await navigator.clipboard.writeText(text);
  showToast(`${label} copied`);
}

function renderItem(login) {
  const item = document.createElement("div");
  item.className = "item";

  const tile = document.createElement("div");
  tile.className = "tile";
  tile.textContent = (login.title || "?").charAt(0).toUpperCase();

  const info = document.createElement("div");
  info.className = "info";
  const title = document.createElement("div");
  title.className = "title";
  title.textContent = login.title;
  const sub = document.createElement("div");
  sub.className = "sub";
  // Search results saved for another site also say which site
  const otherSite = login.site && login.matches_site === false ? login.site : "";
  sub.textContent = [login.username, login.vault, otherSite].filter(Boolean).join(" · ");
  info.append(title, sub);

  const copyUser = document.createElement("button");
  copyUser.className = "icon-btn";
  copyUser.title = "Copy username";
  copyUser.setAttribute("aria-label", "Copy username");
  copyUser.append(icon("person"));
  copyUser.addEventListener("click", () => copyText(login.username, "Username"));

  const copyPass = document.createElement("button");
  copyPass.className = "icon-btn";
  copyPass.title = "Copy password";
  copyPass.setAttribute("aria-label", "Copy password");
  copyPass.append(icon("key"));
  copyPass.addEventListener("click", async () => {
    try {
      // The password is fetched only now, one at a time
      const { password } = await api(`/logins/${encodeURIComponent(login.id)}/password`);
      await copyText(password, "Password");
    } catch (err) {
      handleError(err);
    }
  });

  if (!login.username) copyUser.disabled = true;
  const actions = document.createElement("div");
  actions.className = "actions";
  const buttons = [copyUser, copyPass];
  const menuItems = [];
  if (login.can_edit) menuItems.push({ label: "Edit", onSelect: () => openEditForm(login.id) });
  if (login.can_delete) menuItems.push({ label: "Move to Trash", danger: true, onSelect: () => trashLogin(login) });
  if (menuItems.length) buttons.push(moreButton(`More options for ${login.title}`, menuItems));
  actions.append(...buttons);
  item.append(tile, info, actions);
  return item;
}

async function trashLogin(login) {
  const yes = await confirmBox(`Move "${login.title}" to the Trash? You can restore it in GrishaKey.`, "Move to Trash");
  if (!yes) return;
  try {
    await api(`/logins/${encodeURIComponent(login.id)}`, { method: "DELETE" });
    // Stay on the search results if a search is showing
    if ($("search").value.trim()) await runSearch();
    else await showLogins();
    showToast("Moved to Trash");
  } catch (err) {
    if (err.message === "signed-out") handleError(err);
    else setStatus(err.message, true);
  }
}

// First screen after start-up or sign-in: the form when opened as a window, otherwise the list
async function showStartScreen() {
  if (windowMode === "new") {
    await openNewForm(pageParams.get("site"));
  } else if (windowMode === "edit" && pageParams.get("id")) {
    await openEditForm(pageParams.get("id"));
  } else {
    await showLogins();
  }
}

async function showLogins() {
  setHeader("home");
  updateAvatar();
  hide("vaults");
  editingId = null;
  hide("new");
  hide("login");
  show("list");
  // The site's own list: any search is cleared (back from the form, or the box was emptied)
  clearTimeout(searchTimer);
  searchRequest++;
  $("search").value = "";
  const url = await currentTabUrl();
  let host = "";
  try { host = new URL(url).hostname; } catch { /* not a web page */ }
  if (host) {
    const strong = document.createElement("strong");
    strong.textContent = host;
    $("site").replaceChildren("Logins for ", strong);
  } else {
    $("site").textContent = "Open a website to see its logins.";
  }
  $("items").replaceChildren();
  if (!host) return;

  const request = searchRequest;
  try {
    const logins = await api(`/logins?url=${encodeURIComponent(url)}`);
    if (request !== searchRequest) return;     // a search started while this was loading
    if (logins.length === 0) {
      setStatus("No saved logins for this site.");
      return;
    }
    hide("status");
    logins.forEach((login) => $("items").append(renderItem(login)));
  } catch (err) {
    handleError(err);
  }
}

// ===== Search (every login, any site) =====
let searchTimer = null;
let searchRequest = 0;      // number of the latest search; replies to older ones are ignored

async function runSearch() {
  const q = $("search").value.trim();
  if (!q) { await showLogins(); return; }
  const request = ++searchRequest;
  // Only the tab's origin is sent: matching uses the host, and long addresses stay under the limit
  let origin = "";
  try {
    const page = new URL(await currentTabUrl());
    if (page.protocol === "http:" || page.protocol === "https:") origin = page.origin;
  } catch { /* not a web page */ }
  const query = new URLSearchParams({ q });
  if (origin) query.set("url", origin);
  try {
    const results = await api(`/logins/search?${query}`);
    if (request !== searchRequest) return;   // a newer search (or a cleared box) replaced this one
    $("site").textContent = `Results for "${q}"`;
    $("items").replaceChildren();
    if (results.length === 0) {
      setStatus("No logins match.");
      return;
    }
    hide("status");
    results.forEach((login) => $("items").append(renderItem(login)));
  } catch (err) {
    if (request === searchRequest) handleError(err);
  }
}

$("search").addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchRequest++;          // any reply still on its way is now out of date
  if (!$("search").value.trim()) { showLogins(); return; }
  searchTimer = setTimeout(runSearch, 200);
});

$("search").addEventListener("keydown", (event) => {
  // Escape clears the search and goes back to this site's logins
  if (event.key === "Escape" && $("search").value) {
    event.preventDefault();
    event.stopPropagation();
    showLogins();
  }
});

function showLogin() {
  setHeader(null);
  hide("list");
  hide("new");
  show("login");
  $("email").focus();
}

function handleError(err) {
  if (err.message === "signed-out") {
    showLogin();
  } else {
    setStatus(err.message || "Something went wrong.", true);
  }
}

$("login").addEventListener("submit", async (event) => {
  event.preventDefault();
  hide("login-error");
  try {
    const { token } = await api("/login", {
      method: "POST",
      body: JSON.stringify({ email: $("email").value, password: $("password").value }),
    });
    $("password").value = "";
    await chrome.storage.session.set({ token, email: $("email").value.trim() });
    await showStartScreen();
  } catch (err) {
    $("login-error").replaceChildren(icon("alert"), err.message === "signed-out" ? "Incorrect email or password" : err.message);
    show("login-error");
  }
});

$("logout").addEventListener("click", async () => {
  try { await api("/logout", { method: "POST" }); } catch { /* already signed out */ }
  await chrome.storage.session.remove(["token", "email"]);
  showLogin();
});

$("open-settings").addEventListener("click", () => chrome.runtime.openOptionsPage());

// Fixed icons, set once
setIcon("logout", "logout");
setIcon("nl-back", "back");
setIcon("pw-show", "eye");
setIcon("nl-show", "eye");
setIcon("nl-gen", "dice");
setIcon("toast-icon", "check");
setIcon("toast-close", "close");
$("new-login").prepend(icon("plus"));
updateThemeIcon();

$("toast-close").addEventListener("click", () => hide("toast"));
$("theme-toggle").addEventListener("click", async () => { await toggleTheme(); updateThemeIcon(); });
$("nl-back").addEventListener("click", () => {
  if (windowMode) { window.close(); return; }
  showLogins();
});
$("pw-show").addEventListener("click", () => {
  const hidden = $("password").type === "password";
  $("password").type = hidden ? "text" : "password";
  setIcon("pw-show", hidden ? "eye-off" : "eye");
});

// ===== New login (and new vault) =====
const NEW_VAULT = "__new__";

// The new-login form doubles as the edit form. null = new login, otherwise the login being edited.
let editingId = null;

function setFormMode(mode) {
  const editing = mode === "edit";
  $("formbar-title").textContent = editing ? "Edit login" : "New login";
  $("nl-submit").textContent = editing ? "Save changes" : "Save login";
  $("nl-vault-row").classList.toggle("hidden", editing);
  if (editing) hide("nv-row");
}

function showNewError(text) {
  $("nl-error").replaceChildren(icon("alert"), text);
  show("nl-error");
  $("nl-error").scrollIntoView({ block: "nearest", behavior: "smooth" });
}

function addVaultOption(id, name, select = false) {
  const option = document.createElement("option");
  option.value = id;
  option.textContent = name;
  const newOption = [...$("nl-vault").options].find((o) => o.value === NEW_VAULT);
  $("nl-vault").insertBefore(option, newOption || null);
  if (select) $("nl-vault").value = id;
}

function setPasswordVisible(visible) {
  $("nl-password").type = visible ? "text" : "password";
  setIcon("nl-show", visible ? "eye-off" : "eye");
}

async function openNewForm(prefillUrl = null) {
  editingId = null;
  setHeader("form");
  setFormMode("new");
  hide("vaults");
  hide("list");
  hide("nl-error");
  hide("nv-row");
  hide("gen-panel");
  $("gen-preview").textContent = "";
  show("new");
  $("new").reset();
  setPasswordVisible(false);

  // Prefill from the current tab: the site's origin only, never the full address
  const url = prefillUrl || await currentTabUrl();
  try {
    const page = new URL(url);
    if (page.protocol === "http:" || page.protocol === "https:") {
      $("nl-url").value = page.origin;
      $("nl-title").value = page.hostname.replace(/^www\./, "");
    }
  } catch { /* not a web page */ }

  // Vaults you can add to, plus "+ New vault…"
  $("nl-vault").replaceChildren();
  const newOption = document.createElement("option");
  newOption.value = NEW_VAULT;
  newOption.textContent = "+ New vault…";
  $("nl-vault").append(newOption);
  try {
    const vaults = await api("/vaults");
    vaults.filter((v) => v.can_edit).forEach((v) => addVaultOption(v.id, v.name));
  } catch (err) {
    handleError(err);
    return;
  }
  $("nl-vault").selectedIndex = 0;
  if ($("nl-vault").value === NEW_VAULT) show("nv-row");
  $("nl-title").focus();
}

async function openEditForm(loginId) {
  editingId = loginId;
  setHeader("form");
  setFormMode("edit");
  hide("list");
  hide("vaults");
  hide("nl-error");
  hide("gen-panel");
  show("new");
  $("new").reset();
  $("gen-preview").textContent = "";
  setPasswordVisible(false);
  try {
    // Details and password are fetched separately; the password stays hidden until the eye is clicked
    const details = await api(`/logins/${encodeURIComponent(loginId)}`);
    const { password } = await api(`/logins/${encodeURIComponent(loginId)}/password`);
    $("nl-title").value = details.title;
    $("nl-url").value = details.url;
    $("nl-username").value = details.username;
    $("nl-password").value = password;
    $("nl-notes").value = details.notes;
    $("nl-title").focus();
  } catch (err) {
    if (err.message === "signed-out") handleError(err);
    else showNewError(err.message);
  }
}

$("new-login").addEventListener("click", () => openNewForm());
$("nl-cancel").addEventListener("click", () => {
  if (windowMode) { window.close(); return; }
  showLogins();
});

$("nl-vault").addEventListener("change", () => {
  if ($("nl-vault").value === NEW_VAULT) {
    show("nv-row");
    $("nv-name").focus();
  } else {
    hide("nv-row");
  }
});

$("nv-create").addEventListener("click", async () => {
  hide("nl-error");
  const name = $("nv-name").value.trim();
  if (!name) { showNewError("Give the vault a name."); return; }
  try {
    const created = await api("/vaults", { method: "POST", body: JSON.stringify({ name }) });
    addVaultOption(created.id, created.name, true);
    $("nv-name").value = "";
    hide("nv-row");
    showToast(`Vault "${created.name}" created`);
  } catch (err) {
    if (err.message === "signed-out") handleError(err);
    else showNewError(err.message);
  }
});

$("nl-show").addEventListener("click", () => {
  setPasswordVisible($("nl-password").type === "password");
});

// ===== Password generator panel =====
const GEN_DEFAULTS = {
  mode: "password",
  length: 20, upper: true, lower: true, digits: true, symbols: true,
  words: 5, separator: "-", capitalize: true, number: true,
};
const GEN_SETS = ["upper", "lower", "digits", "symbols"];
const GEN_SEPARATORS = ["-", " ", ".", "_"];
let genTimer = null;
let genRequest = 0;         // number of the latest preview request
let genMode = "password";   // "password" (characters) or "passphrase" (words)

function genOptions() {
  const options = { mode: genMode, length: Number($("gen-length").value) };
  GEN_SETS.forEach((name) => { options[name] = $(`gen-${name}`).checked; });
  options.words = Number($("gen-words").value);
  options.separator = $("gen-separator").value;
  options.capitalize = $("gen-capitalize").checked;
  options.number = $("gen-number").checked;
  return options;
}

// Show the options for characters or for words, and mark the active switch button
function setGenMode(mode) {
  genMode = mode === "passphrase" ? "passphrase" : "password";
  $("gen-mode-password").setAttribute("aria-pressed", String(genMode === "password"));
  $("gen-mode-passphrase").setAttribute("aria-pressed", String(genMode === "passphrase"));
  $("gen-password-opts").classList.toggle("hidden", genMode !== "password");
  $("gen-passphrase-opts").classList.toggle("hidden", genMode !== "passphrase");
}

async function loadGenOptions() {
  // Only the options are remembered, never a password
  const { genOptions: saved } = await chrome.storage.local.get("genOptions");
  const options = { ...GEN_DEFAULTS, ...(saved || {}) };
  $("gen-length").value = options.length;
  $("gen-length-value").textContent = $("gen-length").value;
  GEN_SETS.forEach((name) => { $(`gen-${name}`).checked = Boolean(options[name]); });
  $("gen-words").value = options.words;
  $("gen-words-value").textContent = $("gen-words").value;
  $("gen-separator").value = GEN_SEPARATORS.includes(options.separator) ? options.separator : "-";
  $("gen-capitalize").checked = Boolean(options.capitalize);
  $("gen-number").checked = Boolean(options.number);
  setGenMode(options.mode);
}

async function refreshPreview() {
  const options = genOptions();
  chrome.storage.local.set({ genOptions: options });
  // Each mode sends only its own options
  const path = genMode === "passphrase" ? "/generate-passphrase" : "/generate";
  const keys = genMode === "passphrase"
    ? ["words", "separator", "capitalize", "number"]
    : ["length", ...GEN_SETS];
  const query = new URLSearchParams(keys.map((k) => [k, String(options[k])]));
  const request = ++genRequest;
  try {
    const { password } = await api(`${path}?${query}`);
    // Ignore a slow reply if a newer request was sent since (e.g. after switching modes)
    if (request !== genRequest) return;
    $("gen-preview").textContent = password;
  } catch (err) {
    if (err.message === "signed-out") handleError(err);
    else showNewError(err.message);
  }
}

function refreshSoon() {
  clearTimeout(genTimer);
  genTimer = setTimeout(refreshPreview, 150);
}

setIcon("gen-refresh", "refresh");

$("nl-gen").addEventListener("click", async () => {
  if (!$("gen-panel").classList.contains("hidden")) {
    hide("gen-panel");
    return;
  }
  await loadGenOptions();
  show("gen-panel");
  await refreshPreview();
});

$("gen-length").addEventListener("input", () => {
  $("gen-length-value").textContent = $("gen-length").value;
  refreshSoon();
});

GEN_SETS.forEach((name) => {
  $(`gen-${name}`).addEventListener("change", () => {
    // At least one set must stay on
    if (!GEN_SETS.some((n) => $(`gen-${n}`).checked)) $(`gen-${name}`).checked = true;
    refreshSoon();
  });
});

$("gen-words").addEventListener("input", () => {
  $("gen-words-value").textContent = $("gen-words").value;
  refreshSoon();
});

["gen-separator", "gen-capitalize", "gen-number"].forEach((id) => {
  $(id).addEventListener("change", refreshSoon);
});

$("gen-mode-password").addEventListener("click", () => { setGenMode("password"); refreshPreview(); });
$("gen-mode-passphrase").addEventListener("click", () => { setGenMode("passphrase"); refreshPreview(); });

$("gen-refresh").addEventListener("click", refreshPreview);

$("gen-use").addEventListener("click", () => {
  const password = $("gen-preview").textContent;
  if (!password) return;
  $("nl-password").value = password;
  setPasswordVisible(true);
  hide("gen-panel");
  $("gen-preview").textContent = "";
});

$("new").addEventListener("submit", async (event) => {
  event.preventDefault();
  hide("nl-error");
  if (editingId) {
    try {
      await api(`/logins/${encodeURIComponent(editingId)}`, {
        method: "PUT",
        body: JSON.stringify({
          title: $("nl-title").value.trim(),
          url: $("nl-url").value.trim(),
          username: $("nl-username").value.trim(),
          password: $("nl-password").value,
          notes: $("nl-notes").value,
        }),
      });
      editingId = null;
      $("nl-password").value = "";
      if (windowMode) { window.close(); return; }
      await showLogins();
      showToast("Changes saved");
    } catch (err) {
      if (err.message === "signed-out") handleError(err);
      else showNewError(err.message);
    }
    return;
  }
  if ($("nl-vault").value === NEW_VAULT) { showNewError("Create the vault first, or pick one."); return; }
  try {
    await api("/logins", {
      method: "POST",
      body: JSON.stringify({
        vault_id: $("nl-vault").value,
        title: $("nl-title").value.trim(),
        url: $("nl-url").value.trim(),
        username: $("nl-username").value.trim(),
        password: $("nl-password").value,
        notes: $("nl-notes").value,
      }),
    });
    $("nl-password").value = "";
    if (windowMode) { window.close(); return; }
    await showLogins();
    showToast("Login saved");
  } catch (err) {
    if (err.message === "signed-out") handleError(err);
    else showNewError(err.message);
  }
});

// ===== Vaults screen =====
function vaultRole(v) {
  if (v.is_owner) return "Owner";
  return v.can_edit ? "Shared · can edit" : "Shared · view only";
}

function renderVaultRow(v) {
  const item = document.createElement("div");
  item.className = "item";

  const tile = document.createElement("div");
  tile.className = "tile";
  tile.textContent = (v.name || "?").charAt(0).toUpperCase();

  const info = document.createElement("div");
  info.className = "info";
  const title = document.createElement("div");
  title.className = "title";
  title.textContent = v.name;
  const role = document.createElement("div");
  role.className = "vault-role";
  role.textContent = vaultRole(v);
  info.append(title, role);

  item.append(tile, info);

  if (v.is_owner) {
    const edit = document.createElement("button");
    edit.className = "icon-btn";
    edit.title = "Rename vault";
    edit.setAttribute("aria-label", `Rename ${v.name}`);
    edit.append(icon("edit"));
    edit.addEventListener("click", () => startRename(item, v));
    item.append(edit);
  }
  return item;
}

function startRename(item, v) {
  const row = document.createElement("div");
  row.className = "rename-row";
  const input = document.createElement("input");
  input.value = v.name;
  input.maxLength = 100;
  input.setAttribute("aria-label", "Vault name");
  const save = document.createElement("button");
  save.type = "button";
  save.className = "small-primary";
  save.textContent = "Save";
  const cancel = document.createElement("button");
  cancel.type = "button";
  cancel.className = "link";
  cancel.textContent = "Cancel";
  row.append(input, save, cancel);

  const tile = item.firstElementChild;
  item.replaceChildren(tile, row);
  input.focus();
  input.select();

  cancel.addEventListener("click", showVaults);
  const submit = async () => {
    const name = input.value.trim();
    if (!name) { setVaultsStatus("Give the vault a name.", true); return; }
    try {
      await api(`/vaults/${encodeURIComponent(v.id)}`, { method: "PATCH", body: JSON.stringify({ name }) });
      await showVaults();
      showToast("Vault renamed");
    } catch (err) {
      if (err.message === "signed-out") handleError(err);
      else setVaultsStatus(err.message, true);
    }
  };
  save.addEventListener("click", submit);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") submit();
    if (e.key === "Escape") showVaults();
  });
}

function setVaultsStatus(text, isError = false) {
  const status = $("vaults-status");
  if (isError) status.replaceChildren(icon("alert"), text);
  else status.textContent = text;
  status.classList.toggle("error", isError);
  show("vaults-status");
}

async function showVaults() {
  setHeader("form");
  $("formbar-title").textContent = "Vaults";
  hide("list");
  hide("new");
  hide("vaults-status");
  show("vaults");
  $("vault-items").replaceChildren();
  try {
    const vaults = await api("/vaults");
    if (vaults.length === 0) setVaultsStatus("No vaults yet.");
    vaults.forEach((v) => $("vault-items").append(renderVaultRow(v)));
  } catch (err) {
    handleError(err);
  }
}

setIcon("open-vaults", "vault");
$("open-vaults").addEventListener("click", showVaults);

(async function start() {
  if (!(await getServer())) {
    setHeader(null);
    show("setup");
    return;
  }
  if (await getToken()) {
    await showStartScreen();
  } else {
    showLogin();
  }
})();

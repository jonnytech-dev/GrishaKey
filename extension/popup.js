// GrishaKey popup: sign in, show logins for the current site, copy on click.
// Server data is only ever put on the page with textContent (never innerHTML).

const $ = (id) => document.getElementById(id);
const show = (id) => $(id).classList.remove("hidden");
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
  sub.textContent = [login.username, login.vault].filter(Boolean).join(" · ");
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
  actions.append(copyUser, copyPass);
  item.append(tile, info, actions);
  return item;
}

async function showLogins() {
  setHeader("home");
  updateAvatar();
  hide("new");
  hide("login");
  show("list");
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

  try {
    const logins = await api(`/logins?url=${encodeURIComponent(url)}`);
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
    await showLogins();
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
$("nl-back").addEventListener("click", showLogins);
$("pw-show").addEventListener("click", () => {
  const hidden = $("password").type === "password";
  $("password").type = hidden ? "text" : "password";
  setIcon("pw-show", hidden ? "eye-off" : "eye");
});

// ===== New login (and new vault) =====
const NEW_VAULT = "__new__";

function showNewError(text) {
  $("nl-error").replaceChildren(icon("alert"), text);
  show("nl-error");
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

async function openNewForm() {
  setHeader("form");
  hide("list");
  hide("nl-error");
  hide("nv-row");
  show("new");
  $("new").reset();
  setPasswordVisible(false);

  // Prefill from the current tab: the site's origin only, never the full address
  const url = await currentTabUrl();
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

$("new-login").addEventListener("click", openNewForm);
$("nl-cancel").addEventListener("click", showLogins);

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

$("nl-gen").addEventListener("click", async () => {
  try {
    const { password } = await api("/generate?length=20");
    $("nl-password").value = password;
    setPasswordVisible(true);
  } catch (err) {
    if (err.message === "signed-out") handleError(err);
    else showNewError(err.message);
  }
});

$("new").addEventListener("submit", async (event) => {
  event.preventDefault();
  hide("nl-error");
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
    await showLogins();
    showToast("Login saved");
  } catch (err) {
    if (err.message === "signed-out") handleError(err);
    else showNewError(err.message);
  }
});

(async function start() {
  if (!(await getServer())) {
    setHeader(null);
    show("setup");
    return;
  }
  if (await getToken()) {
    await showLogins();
  } else {
    showLogin();
  }
})();

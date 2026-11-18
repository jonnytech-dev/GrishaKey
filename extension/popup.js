// GrishaKey popup: sign in, show logins for the current site, copy on click.
// Server data is only ever put on the page with textContent (never innerHTML).

const $ = (id) => document.getElementById(id);
const show = (id) => $(id).classList.remove("hidden");
const hide = (id) => $(id).classList.add("hidden");

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
  const response = await fetch(`${server}/api/v1${path}`, { ...options, headers });
  if (response.status === 401) {
    await chrome.storage.session.remove("token");
    throw new Error("signed-out");
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed (${response.status})`);
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
  setStatus(`${label} copied.`);
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
  copyUser.className = "icon";
  copyUser.textContent = "User";
  copyUser.title = "Copy username";
  copyUser.addEventListener("click", () => copyText(login.username, "Username"));

  const copyPass = document.createElement("button");
  copyPass.className = "icon";
  copyPass.textContent = "Pass";
  copyPass.title = "Copy password";
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
  item.append(tile, info, copyUser, copyPass);
  return item;
}

async function showLogins() {
  hide("login");
  show("logout");
  show("list");
  const url = await currentTabUrl();
  let host = "";
  try { host = new URL(url).hostname; } catch { /* not a web page */ }
  $("site").textContent = host ? `Logins for ${host}` : "Open a website to see its logins.";
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
  hide("list");
  hide("logout");
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
    await chrome.storage.session.set({ token });
    await showLogins();
  } catch (err) {
    $("login-error").textContent = err.message === "signed-out" ? "Incorrect email or password" : err.message;
    show("login-error");
  }
});

$("logout").addEventListener("click", async () => {
  try { await api("/logout", { method: "POST" }); } catch { /* already signed out */ }
  await chrome.storage.session.remove("token");
  showLogin();
});

$("open-settings").addEventListener("click", () => chrome.runtime.openOptionsPage());

(async function start() {
  if (!(await getServer())) {
    show("setup");
    return;
  }
  if (await getToken()) {
    await showLogins();
  } else {
    showLogin();
  }
})();

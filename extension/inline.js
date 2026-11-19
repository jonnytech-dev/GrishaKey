// The dropdown under a login field. It runs as an extension page inside an iframe,
// so the website can't read anything shown here.
const $ = (id) => document.getElementById(id);

function message(text, isError = false) {
  $("msg").textContent = text;
  $("msg").classList.toggle("error", isError);
}

function send(payload) {
  return chrome.runtime.sendMessage(payload);
}

// Eye icons for the password field (built without innerHTML)
function eyeIcon(open) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  const path = document.createElementNS(ns, "path");
  path.setAttribute("d", open
    ? "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"
    : "M3 3l18 18M10.6 10.6a3 3 0 0 0 4.2 4.2M9.9 5.2A10.4 10.4 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.2M6.6 6.6C3.8 8.4 2 12 2 12s3.5 7 10 7c1.7 0 3.2-.4 4.5-1.1");
  svg.append(path);
  return svg;
}

// Ask the page to size this frame to fit what's showing (smoothly)
function fitFrame() {
  requestAnimationFrame(() => {
    send({ type: "gk-resize", height: Math.ceil(document.body.scrollHeight) + 2 });
  });
}

function showSignIn(errorText = "") {
  $("list-area").classList.add("hidden");
  $("head-brand").classList.add("hidden");
  $("signin").classList.remove("hidden");
  $("signin").classList.add("fade-in");
  if (errorText) {
    $("si-error").replaceChildren(errorText);
    $("si-error").classList.remove("hidden");
  }
  $("si-email").focus();
  fitFrame();
}

function showList() {
  $("signin").classList.add("hidden");
  $("head-brand").classList.remove("hidden");
  $("list-area").classList.remove("hidden");
  $("list-area").classList.add("fade-in");
}

let pageHost = "";        // the clicked page's host, as the background reports it (never from the page)
let searchTimer = null;
let searchRequest = 0;    // number of the latest search; replies to older ones are ignored

function renderItem(login) {
  // Search results carry matches_site; the site's own list doesn't (those all match)
  const otherSite = login.matches_site === false;
  const button = document.createElement("button");
  button.className = "item";

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
  sub.textContent = login.username || "No username";
  info.append(title, sub);
  if (otherSite && login.site) {
    const note = document.createElement("div");
    note.className = "other-site";
    note.textContent = `Saved for ${login.site}`;
    info.append(note);
  }

  button.append(tile, info);
  button.addEventListener("click", async () => {
    let payload = { type: "gk-fill", entryId: login.id };
    if (otherSite) {
      // Saved for a different site: ask before filling it here
      const savedFor = login.site ? `is saved for ${login.site}` : "has no website saved";
      const yes = await confirmBox(`"${login.title}" ${savedFor}. Fill it on ${pageHost || "this page"} anyway?`, "Fill anyway");
      if (!yes) return;
      payload = { type: "gk-fill", entryId: login.id, title: login.title, allowOtherSite: true };
    }
    message("Filling…");
    const reply = await send(payload);
    if (reply?.error) {
      if (reply.error === "signed-out") { showSignIn("You were signed out. Sign in again."); return; }
      message(reply.error, true);
    }
  });

  const row = document.createElement("div");
  row.className = "item-row";
  row.append(button);

  // Edit and Move to Trash only work here for this site's logins (background.js checks the site)
  if (otherSite) return row;
  const menuItems = [];
  if (login.can_edit) menuItems.push({ label: "Edit", onSelect: () => send({ type: "gk-open-editor", mode: "edit", entryId: login.id }) });
  if (login.can_delete) menuItems.push({ label: "Move to Trash", danger: true, onSelect: () => trashLogin(login) });
  if (menuItems.length) row.append(moreButton(`More options for ${login.title}`, menuItems));
  return row;
}

async function trashLogin(login) {
  const yes = await confirmBox(`Move "${login.title}" to the Trash?`, "Move to Trash");
  if (!yes) return;
  const reply = await send({ type: "gk-delete", entryId: login.id });
  if (reply?.error) {
    if (reply.error === "signed-out") { showSignIn("You were signed out. Sign in again."); return; }
    message(reply.error, true);
    return;
  }
  $("items").replaceChildren();
  message("");
  if ($("search").value.trim()) await runSearch();
  else await loadLogins();
}

$("new-login").addEventListener("click", () => send({ type: "gk-open-editor", mode: "new" }));

async function loadLogins() {
  const reply = await send({ type: "gk-get-logins" });
  if (reply?.error === "signed-out" || (reply && !reply.error && !reply.signedIn)) {
    showSignIn();
    return;
  }
  // Other errors show in the list area's message line, so the list area must be visible
  showList();
  $("search").focus();
  if (reply?.error) {
    message(reply.error, true);
    fitFrame();
    return;
  }
  pageHost = reply.host;
  // The user started a search while this list was loading: the search shows its own results
  if ($("search").value.trim()) return;
  const strong = document.createElement("strong");
  strong.textContent = reply.host;
  $("site").replaceChildren("Logins for ", strong);
  $("items").replaceChildren();
  message("");
  if (reply.logins.length === 0) {
    message("No saved logins for this site.");
    fitFrame();
    return;
  }
  reply.logins.forEach((login) => $("items").append(renderItem(login)));
  fitFrame();
}

// Search every login. Results come back without passwords; a password is fetched only on fill.
async function runSearch() {
  const q = $("search").value.trim();
  const request = ++searchRequest;
  if (!q) { await loadLogins(); return; }
  const reply = await send({ type: "gk-search", q });
  if (request !== searchRequest) return;      // a newer search (or a cleared box) replaced this one
  if (reply?.error) {
    if (reply.error === "signed-out") { showSignIn("You were signed out. Sign in again."); return; }
    message(reply.error, true);
    fitFrame();
    return;
  }
  $("site").textContent = `Results for "${q}"`;
  $("items").replaceChildren();
  message("");
  if (reply.results.length === 0) message("No logins match.");
  else reply.results.forEach((login) => $("items").append(renderItem(login)));
  fitFrame();
}

// Back to "Logins for <site>"
function clearSearch() {
  clearTimeout(searchTimer);
  searchRequest++;
  $("search").value = "";
  loadLogins();
}

$("search").addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchRequest++;          // any reply still on its way is now out of date
  if (!$("search").value.trim()) { clearSearch(); return; }
  searchTimer = setTimeout(runSearch, 200);
});

$("search").addEventListener("keydown", (event) => {
  // Escape with text clears the search; on an empty box it closes the dropdown as before
  if (event.key === "Escape" && $("search").value) {
    event.preventDefault();
    event.stopPropagation();
    clearSearch();
  }
});

$("si-show").append(eyeIcon(true));
$("si-show").addEventListener("click", () => {
  const hidden = $("si-password").type === "password";
  $("si-password").type = hidden ? "text" : "password";
  $("si-show").replaceChildren(eyeIcon(!hidden));
  $("si-show").setAttribute("aria-label", hidden ? "Hide password" : "Show password");
});

$("signin").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("si-error").classList.add("hidden");
  $("si-submit").disabled = true;
  $("si-submit").textContent = "Signing in…";
  const reply = await send({ type: "gk-login", email: $("si-email").value.trim(), password: $("si-password").value });
  $("si-submit").disabled = false;
  $("si-submit").textContent = "Sign in";
  $("si-password").value = "";
  if (reply?.error) {
    $("si-error").replaceChildren(reply.error);
    $("si-error").classList.remove("hidden");
    fitFrame();
    return;
  }
  await loadLogins();
});

loadLogins();

$("close").addEventListener("click", () => send({ type: "gk-close" }));
document.addEventListener("keydown", (event) => { if (event.key === "Escape") send({ type: "gk-close" }); });

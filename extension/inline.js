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

function renderItem(login) {
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

  button.append(tile, info);
  button.addEventListener("click", async () => {
    message("Filling…");
    const reply = await send({ type: "gk-fill", entryId: login.id });
    if (reply?.error) {
      message(reply.error === "signed-out" ? "Signed out. Click the GrishaKey toolbar icon to sign in." : reply.error, true);
    }
  });
  return button;
}

(async function start() {
  const reply = await send({ type: "gk-get-logins" });
  if (reply?.error) {
    message(reply.error === "signed-out" ? "Signed out. Click the GrishaKey toolbar icon to sign in." : reply.error, true);
    return;
  }
  if (!reply.signedIn) {
    message("Click the GrishaKey toolbar icon to sign in.");
    return;
  }
  const strong = document.createElement("strong");
  strong.textContent = reply.host;
  $("site").replaceChildren("Logins for ", strong);
  if (reply.logins.length === 0) {
    message("No saved logins for this site.");
    return;
  }
  reply.logins.forEach((login) => $("items").append(renderItem(login)));
  $("items").querySelector("button")?.focus();
})();

$("close").addEventListener("click", () => send({ type: "gk-close" }));
document.addEventListener("keydown", (event) => { if (event.key === "Escape") send({ type: "gk-close" }); });

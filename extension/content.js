// GrishaKey in-page icon. Runs on websites ONLY if the user turned on in-page autofill.
// It never sees the list of logins or the token. It only shows an icon, opens the
// extension's dropdown frame, and fills the two fields when the background says to.
(() => {
  if (window.__grishakeyLoaded) return;
  window.__grishakeyLoaded = true;

  const ICON_SIZE = 22;
  const marked = new WeakSet();     // password fields that already have an icon
  let active = null;                // { username, password, frame } for the open dropdown

  function isVisible(el) {
    if (!el || !el.isConnected || el.disabled || el.readOnly) return false;
    const style = getComputedStyle(el);
    const box = el.getBoundingClientRect();
    return style.visibility !== "hidden" && style.display !== "none" &&
           Number(style.opacity) > 0.1 && box.width > 20 && box.height > 10;
  }

  // The username field: the last visible text/email/tel input before the password field
  function findUsernameField(passwordField) {
    const scope = passwordField.form || document;
    const inputs = [...scope.querySelectorAll("input")];
    const index = inputs.indexOf(passwordField);
    for (let i = index - 1; i >= 0; i--) {
      const input = inputs[i];
      if (["text", "email", "tel", ""].includes(input.type) && isVisible(input)) return input;
    }
    return null;
  }

  // Set a value the way typing would, so React/Vue/Angular sites notice it
  function setValue(input, value) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    input.focus();
    setter.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function closeDropdown() {
    if (active?.frame) active.frame.remove();
    active = null;
  }

  function openDropdown(passwordField, anchorField) {
    closeDropdown();
    const box = anchorField.getBoundingClientRect();
    const frame = document.createElement("iframe");
    frame.src = chrome.runtime.getURL("inline.html");
    frame.title = "GrishaKey";
    Object.assign(frame.style, {
      position: "absolute",
      top: `${window.scrollY + box.bottom + 6}px`,
      left: `${window.scrollX + Math.max(8, box.left)}px`,
      width: "300px",
      height: "260px",
      border: "0",
      borderRadius: "14px",
      boxShadow: "0 20px 50px -12px rgba(0,0,0,0.35)",
      zIndex: "2147483647",
      colorScheme: "normal",
    });
    document.body.appendChild(frame);
    active = { username: findUsernameField(passwordField), password: passwordField, frame };
    chrome.runtime.sendMessage({ type: "gk-open" });
  }

  // The small icon. A shadow root keeps page styles from changing it.
  // It holds NO data, so it doesn't matter that the page can see it exists.
  function addIcon(passwordField, anchorField) {
    const host = document.createElement("div");
    const shadow = host.attachShadow({ mode: "closed" });
    const button = document.createElement("button");
    button.type = "button";
    button.title = "Fill with GrishaKey";
    button.setAttribute("aria-label", "Fill with GrishaKey");
    Object.assign(button.style, {
      width: `${ICON_SIZE}px`, height: `${ICON_SIZE}px`, padding: "0", border: "0",
      borderRadius: "6px", cursor: "pointer",
      display: "flex", alignItems: "center", justifyContent: "center",
    });
    const img = document.createElement("img");
    img.src = chrome.runtime.getURL("icons/icon-32.png");
    img.alt = "";
    Object.assign(img.style, { width: "100%", height: "100%", borderRadius: "6px", display: "block" });
    button.appendChild(img);
    shadow.appendChild(button);
    Object.assign(host.style, { position: "absolute", zIndex: "2147483646" });
    document.body.appendChild(host);

    function place() {
      if (!isVisible(anchorField)) { host.style.display = "none"; return; }
      const box = anchorField.getBoundingClientRect();
      host.style.display = "block";
      host.style.top = `${window.scrollY + box.top + (box.height - ICON_SIZE) / 2}px`;
      host.style.left = `${window.scrollX + box.right - ICON_SIZE - 8}px`;
    }
    place();
    window.addEventListener("scroll", place, true);
    window.addEventListener("resize", place);
    new ResizeObserver(place).observe(anchorField);

    button.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      openDropdown(passwordField, anchorField);
    });
  }

  function scan() {
    document.querySelectorAll('input[type="password"]').forEach((passwordField) => {
      if (marked.has(passwordField) || !isVisible(passwordField)) return;
      marked.add(passwordField);
      addIcon(passwordField, passwordField);
      const username = findUsernameField(passwordField);
      if (username) addIcon(passwordField, username);
    });
  }

  // Messages from background.js only (content scripts can't be messaged by the page)
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "gk-fill" && active) {
      // Fill only fields that are still there and visible
      if (active.username && message.username && isVisible(active.username)) {
        setValue(active.username, message.username);
      }
      if (isVisible(active.password)) setValue(active.password, message.password);
      closeDropdown();
    }
    if (message.type === "gk-close") closeDropdown();
  });

  document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeDropdown(); });
  document.addEventListener("click", (event) => { if (active && event.target !== active.frame) closeDropdown(); });

  // Login forms often appear after the page loads (single-page apps, pop-up sign-ins)
  let pending = null;
  new MutationObserver(() => {
    clearTimeout(pending);
    pending = setTimeout(scan, 300);
  }).observe(document.documentElement, { childList: true, subtree: true });
  scan();
})();

// A small ⋮ menu and a confirm box, shared by the popup and the in-page dropdown.
// Labels and messages are always set with textContent (they can include login titles).

let openMenuEl = null;

function closeMenu() {
  if (!openMenuEl) return;
  const menu = openMenuEl;
  openMenuEl = null;
  menu.classList.remove("open");
  menu.classList.add("closing");
  setTimeout(() => menu.remove(), 150);
}

// items: [{ label, danger?, onSelect }]
function openMenu(anchor, items) {
  closeMenu();
  const menu = document.createElement("div");
  menu.className = "menu";
  menu.setAttribute("role", "menu");
  items.forEach((item) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "menu-item" + (item.danger ? " danger" : "");
    button.setAttribute("role", "menuitem");
    button.textContent = item.label;
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      closeMenu();
      item.onSelect();
    });
    menu.append(button);
  });
  document.body.append(menu);

  // Open below the button; flip above if there isn't room
  const a = anchor.getBoundingClientRect();
  const m = menu.getBoundingClientRect();
  let top = a.bottom + 4;
  if (top + m.height > window.innerHeight - 4) top = Math.max(4, a.top - m.height - 4);
  const left = Math.max(4, Math.min(a.right - m.width, window.innerWidth - m.width - 4));
  menu.style.top = `${top}px`;
  menu.style.left = `${left}px`;
  requestAnimationFrame(() => menu.classList.add("open"));
  openMenuEl = menu;
  menu.querySelector("button")?.focus();
}

document.addEventListener("click", closeMenu);
document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeMenu(); });

// A three-dot icon, built without innerHTML
function moreIcon() {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "currentColor");
  [5, 12, 19].forEach((y) => {
    const dot = document.createElementNS(ns, "circle");
    dot.setAttribute("cx", "12");
    dot.setAttribute("cy", String(y));
    dot.setAttribute("r", "1.8");
    svg.append(dot);
  });
  return svg;
}

// A ⋮ button that opens a menu with the given items
function moreButton(label, items) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "icon-btn more-btn";
  button.title = "More";
  button.setAttribute("aria-label", label);
  button.setAttribute("aria-haspopup", "menu");
  button.append(moreIcon());
  button.addEventListener("click", (event) => {
    event.stopPropagation();
    if (openMenuEl) { closeMenu(); return; }
    openMenu(button, items);
  });
  return button;
}

// Resolves true if the user confirms
function confirmBox(message, confirmLabel = "Confirm") {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "confirm-overlay";
    const box = document.createElement("div");
    box.className = "confirm-box";
    box.setAttribute("role", "alertdialog");
    const text = document.createElement("p");
    text.textContent = message;
    const actions = document.createElement("div");
    actions.className = "confirm-actions";
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "link";
    cancel.textContent = "Cancel";
    const ok = document.createElement("button");
    ok.type = "button";
    ok.className = "danger-btn";
    ok.textContent = confirmLabel;
    actions.append(cancel, ok);
    box.append(text, actions);
    overlay.append(box);
    document.body.append(overlay);
    requestAnimationFrame(() => overlay.classList.add("open"));
    ok.focus();

    const done = (answer) => {
      overlay.classList.remove("open");
      setTimeout(() => overlay.remove(), 160);
      resolve(answer);
    };
    cancel.addEventListener("click", () => done(false));
    ok.addEventListener("click", () => done(true));
    overlay.addEventListener("click", (event) => { if (event.target === overlay) done(false); });
    overlay.addEventListener("keydown", (event) => { if (event.key === "Escape") done(false); });
  });
}

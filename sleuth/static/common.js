// Shared helpers for Sleuth pages.
const $ = (id) => document.getElementById(id);

function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (v !== undefined && v !== null && v !== false) n.setAttribute(k, v);
  }
  for (const k of kids) if (k !== null && k !== undefined) n.append(k);
  return n;
}

const safeUrl = (u) => (/^https?:\/\//i.test(u || "") ? u : null);

// Theme toggle: auto -> light -> dark, remembered per browser.
(function () {
  const btn = document.getElementById("themeBtn");
  if (!btn) return;
  const icons = {
    auto: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="8"/><path d="M12 4a8 8 0 0 0 0 16z" fill="currentColor"/></svg>',
    light: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
    dark: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/></svg>',
  };
  const names = { auto: "ธีม: ตามระบบ", light: "ธีม: สว่าง", dark: "ธีม: มืด" };
  let mode = document.documentElement.dataset.theme || "auto";
  const apply = () => {
    if (mode === "auto") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = mode;
    btn.innerHTML = icons[mode];
    btn.title = names[mode];
    try { mode === "auto" ? localStorage.removeItem("sleuth-theme") : localStorage.setItem("sleuth-theme", mode); } catch (e) {}
  };
  btn.onclick = () => { mode = { auto: "light", light: "dark", dark: "auto" }[mode]; apply(); };
  apply();
})();
